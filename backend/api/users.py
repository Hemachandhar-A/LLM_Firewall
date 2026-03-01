"""
User Management and Audit Logs API for the Adaptive LLM Firewall.

Provides endpoints for:
- User account management
- Role-based access control (RBAC)
- Audit trail logging
- User activity monitoring
- Session management
- Permission management
"""

import logging
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from uuid import uuid4
from enum import Enum

from fastapi import APIRouter, HTTPException, Query, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, validator

from api.db import log_event
from api.event_emitter import emit_event

logger = logging.getLogger(__name__)

router = APIRouter(tags=["users", "audit"])
security = HTTPBearer()

# In-memory stores (replace with database in production)
USERS = {}
ROLES = {}
PERMISSIONS = {}
AUDIT_LOGS = []
ACTIVE_SESSIONS = {}

class UserRole(str, Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    OPERATOR = "operator"
    VIEWER = "viewer"
    API_USER = "api_user"

class UserStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    LOCKED = "locked"

class AuditAction(str, Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    VIEW = "view"
    POLICY_CHANGE = "policy_change"
    CONFIG_CHANGE = "config_change"
    INTEGRATION_ACCESS = "integration_access"
    API_ACCESS = "api_access"

# ============================================================================
# Request / Response Models
# ============================================================================

class Permission(BaseModel):
    """Permission definition."""
    id: str = Field(..., description="Permission ID")
    name: str = Field(..., description="Permission name")
    description: str = Field(default="", description="Permission description")
    resource: str = Field(..., description="Resource type (policies, integrations, etc.)")
    actions: List[str] = Field(..., description="Allowed actions (read, write, delete, etc.)")

class Role(BaseModel):
    """Role definition with permissions."""
    id: Optional[str] = Field(default=None, description="Role ID")
    name: str = Field(..., description="Role name")
    description: str = Field(default="", description="Role description")
    permissions: List[str] = Field(..., description="List of permission IDs")
    created_at: Optional[datetime] = Field(default=None, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(default=None, description="Last update timestamp")

class User(BaseModel):
    """User account definition."""
    id: Optional[str] = Field(default=None, description="User ID")
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(..., description="User email address")
    full_name: str = Field(..., description="Full name")
    role: UserRole = Field(..., description="User role")
    status: UserStatus = Field(default=UserStatus.ACTIVE, description="User status")
    password_hash: Optional[str] = Field(default=None, description="Hashed password")
    last_login: Optional[datetime] = Field(default=None, description="Last login timestamp")
    login_count: int = Field(default=0, description="Total login count")
    failed_login_attempts: int = Field(default=0, description="Failed login attempts")
    locked_until: Optional[datetime] = Field(default=None, description="Account lock expiration")
    created_at: Optional[datetime] = Field(default=None, description="Creation timestamp")
    created_by: str = Field(default="system", description="Creator identifier")
    preferences: Dict[str, Any] = Field(default_factory=dict, description="User preferences")
    
    class Config:
        exclude = {"password_hash"}  # Don't include in JSON responses

class UserCreate(BaseModel):
    """User creation request."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: str
    role: UserRole
    password: str = Field(..., min_length=8, description="Password (min 8 characters)")
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

class UserUpdate(BaseModel):
    """User update request."""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    status: Optional[UserStatus] = None
    preferences: Optional[Dict[str, Any]] = None

class PasswordChange(BaseModel):
    """Password change request."""
    current_password: str
    new_password: str = Field(..., min_length=8)
    
    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

class UserSession(BaseModel):
    """User session information."""
    session_id: str
    user_id: str
    username: str
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime

class AuditLog(BaseModel):
    """Audit log entry."""
    id: str = Field(..., description="Log entry ID")
    user_id: Optional[str] = Field(default=None, description="User who performed the action")
    username: Optional[str] = Field(default=None, description="Username")
    action: AuditAction = Field(..., description="Action performed")
    resource_type: str = Field(..., description="Type of resource affected")
    resource_id: Optional[str] = Field(default=None, description="ID of affected resource")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")
    ip_address: Optional[str] = Field(default=None, description="Source IP address")
    user_agent: Optional[str] = Field(default=None, description="User agent string")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    success: bool = Field(default=True, description="Whether the action was successful")

class LoginRequest(BaseModel):
    """Login request."""
    username: str
    password: str
    remember_me: bool = Field(default=False, description="Remember session")

class LoginResponse(BaseModel):
    """Login response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: User
    session_id: str

# ============================================================================
# Helper Functions
# ============================================================================

def hash_password(password: str) -> str:
    """Hash a password using SHA-256 (use bcrypt in production)."""
    salt = secrets.token_hex(16)
    return hashlib.sha256((password + salt).encode()).hexdigest() + ":" + salt

def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    try:
        hash_part, salt = password_hash.split(":")
        return hashlib.sha256((password + salt).encode()).hexdigest() == hash_part
    except:
        return False

async def create_audit_log(
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    action: AuditAction = None,
    resource_type: str = None,
    resource_id: Optional[str] = None,
    details: Dict[str, Any] = None,
    success: bool = True,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
):
    """Create an audit log entry."""
    audit_log = AuditLog(
        id=str(uuid4()),
        user_id=user_id,
        username=username,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        success=success,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    AUDIT_LOGS.append(audit_log)
    
    # Keep only last 10000 logs to prevent memory issues
    if len(AUDIT_LOGS) > 10000:
        AUDIT_LOGS[:] = AUDIT_LOGS[-10000:]
    
    # Also log to the main event system
    await log_event({
        "event_type": "audit_log",
        "action": action,
        "resource_type": resource_type,
        "user_id": user_id,
        "success": success,
        "timestamp": audit_log.timestamp.isoformat()
    })

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Get the current authenticated user."""
    try:
        # Parse token (simplified - use JWT in production)
        session_id, user_id = credentials.credentials.split(":")
        
        if session_id not in ACTIVE_SESSIONS:
            raise HTTPException(status_code=401, detail="Session not found")
        
        session = ACTIVE_SESSIONS[session_id]
        
        # Check if session is expired
        if session.expires_at < datetime.now(timezone.utc):
            ACTIVE_SESSIONS.pop(session_id)
            raise HTTPException(status_code=401, detail="Session expired")
        
        # Update last activity
        session.last_activity = datetime.now(timezone.utc)
        
        user = USERS.get(user_id)
        if not user or user.status != UserStatus.ACTIVE:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        return {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "session_id": session_id
        }
        
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token format")
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication failed")

def initialize_default_users():
    """Initialize with default admin user."""
    if not USERS:  # Only initialize if empty
        admin_user = User(
            id="admin-001",
            username="admin",
            email="admin@slingshot.dev",
            full_name="System Administrator",
            role=UserRole.ADMIN,
            password_hash=hash_password("admin123"),  # Change in production!
            created_at=datetime.now(timezone.utc),
            created_by="system"
        )
        USERS[admin_user.id] = admin_user

# Initialize default data
initialize_default_users()

# ============================================================================
# User Management
# ============================================================================

@router.get("/users", response_model=List[User])
async def list_users(
    status: Optional[UserStatus] = Query(None, description="Filter by status"),
    role: Optional[UserRole] = Query(None, description="Filter by role"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of users")
):
    """List all users with optional filtering."""
    users = list(USERS.values())
    
    if status:
        users = [u for u in users if u.status == status]
    
    if role:
        users = [u for u in users if u.role == role]
    
    # Remove password hash from response
    for user in users:
        user.password_hash = None
    
    return users[:limit]

@router.get("/users/{user_id}", response_model=User)
async def get_user(user_id: str):
    """Get a specific user by ID."""
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="User not found")
    
    user = USERS[user_id].copy()
    user.password_hash = None  # Don't expose password hash
    return user

@router.post("/users", response_model=User, status_code=201)
async def create_user(user_create: UserCreate, current_user: dict = Depends(get_current_user)):
    """Create a new user account."""
    # Check if username or email already exists
    for existing_user in USERS.values():
        if existing_user.username == user_create.username:
            raise HTTPException(status_code=400, detail="Username already exists")
        if existing_user.email == user_create.email:
            raise HTTPException(status_code=400, detail="Email already exists")
    
    # Hash the password
    password_hash = hash_password(user_create.password)
    
    user = User(
        id=str(uuid4()),
        username=user_create.username,
        email=user_create.email,
        full_name=user_create.full_name,
        role=user_create.role,
        password_hash=password_hash,
        created_at=datetime.now(timezone.utc),
        created_by=current_user.get("username", "system")
    )
    
    USERS[user.id] = user
    
    # Log the user creation
    await create_audit_log(
        user_id=current_user.get("id"),
        username=current_user.get("username"),
        action=AuditAction.CREATE,
        resource_type="user",
        resource_id=user.id,
        details={"username": user.username, "role": user.role}
    )
    
    emit_event("user_created", {
        "user_id": user.id,
        "username": user.username,
        "role": user.role
    })
    
    user.password_hash = None  # Don't return password hash
    return user

@router.put("/users/{user_id}", response_model=User)
async def update_user(
    user_id: str, 
    user_update: UserUpdate, 
    current_user: dict = Depends(get_current_user)
):
    """Update an existing user."""
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="User not found")
    
    user = USERS[user_id]
    
    # Update fields if provided
    if user_update.email is not None:
        user.email = user_update.email
    if user_update.full_name is not None:
        user.full_name = user_update.full_name
    if user_update.role is not None:
        user.role = user_update.role
    if user_update.status is not None:
        user.status = user_update.status
    if user_update.preferences is not None:
        user.preferences = user_update.preferences
    
    # Log the user update
    await create_audit_log(
        user_id=current_user.get("id"),
        username=current_user.get("username"),
        action=AuditAction.UPDATE,
        resource_type="user",
        resource_id=user_id,
        details=user_update.dict(exclude_none=True)
    )
    
    user.password_hash = None  # Don't return password hash
    return user

@router.delete("/users/{user_id}")
async def delete_user(user_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a user account."""
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Don't allow users to delete themselves
    if user_id == current_user.get("id"):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    deleted_user = USERS.pop(user_id)
    
    # Invalidate all sessions for this user
    sessions_to_remove = [sid for sid, session in ACTIVE_SESSIONS.items() if session.user_id == user_id]
    for session_id in sessions_to_remove:
        ACTIVE_SESSIONS.pop(session_id)
    
    # Log the user deletion
    await create_audit_log(
        user_id=current_user.get("id"),
        username=current_user.get("username"),
        action=AuditAction.DELETE,
        resource_type="user",
        resource_id=user_id,
        details={"username": deleted_user.username}
    )
    
    return {"message": "User deleted successfully"}

# ============================================================================
# Authentication
# ============================================================================

@router.post("/auth/login", response_model=LoginResponse)
async def login(login_request: LoginRequest):
    """Authenticate user and create session."""
    # Find user by username
    user = None
    for u in USERS.values():
        if u.username == login_request.username:
            user = u
            break
    
    if not user:
        await create_audit_log(
            username=login_request.username,
            action=AuditAction.LOGIN,
            resource_type="session",
            success=False,
            details={"reason": "user_not_found"}
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if account is locked
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        await create_audit_log(
            user_id=user.id,
            username=user.username,
            action=AuditAction.LOGIN,
            resource_type="session",
            success=False,
            details={"reason": "account_locked"}
        )
        raise HTTPException(status_code=423, detail="Account is locked")
    
    # Verify password
    if not verify_password(login_request.password, user.password_hash):
        user.failed_login_attempts += 1
        
        # Lock account after 5 failed attempts
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
            user.status = UserStatus.LOCKED
        
        await create_audit_log(
            user_id=user.id,
            username=user.username,
            action=AuditAction.LOGIN,
            resource_type="session",
            success=False,
            details={"reason": "invalid_password", "attempts": user.failed_login_attempts}
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check user status
    if user.status != UserStatus.ACTIVE:
        await create_audit_log(
            user_id=user.id,
            username=user.username,
            action=AuditAction.LOGIN,
            resource_type="session",
            success=False,
            details={"reason": "account_inactive", "status": user.status}
        )
        raise HTTPException(status_code=403, detail="Account is not active")
    
    # Create session
    session_id = str(uuid4())
    expires_in = 3600 if not login_request.remember_me else 86400 * 30  # 1 hour or 30 days
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    
    session = UserSession(
        session_id=session_id,
        user_id=user.id,
        username=user.username,
        ip_address="0.0.0.0",  # Would come from request
        user_agent="Unknown",   # Would come from request
        created_at=datetime.now(timezone.utc),
        last_activity=datetime.now(timezone.utc),
        expires_at=expires_at
    )
    
    ACTIVE_SESSIONS[session_id] = session
    
    # Update user login info
    user.last_login = datetime.now(timezone.utc)
    user.login_count += 1
    user.failed_login_attempts = 0
    user.locked_until = None
    
    # Generate access token (simplified - use JWT in production)
    access_token = f"{session_id}:{user.id}"
    
    await create_audit_log(
        user_id=user.id,
        username=user.username,
        action=AuditAction.LOGIN,
        resource_type="session",
        details={"session_id": session_id}
    )
    
    user.password_hash = None  # Don't return password hash
    return LoginResponse(
        access_token=access_token,
        expires_in=expires_in,
        user=user,
        session_id=session_id
    )

@router.post("/auth/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout user and invalidate session."""
    session_id = current_user.get("session_id")
    
    if session_id and session_id in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS.pop(session_id)
    
    await create_audit_log(
        user_id=current_user.get("id"),
        username=current_user.get("username"),
        action=AuditAction.LOGOUT,
        resource_type="session",
        details={"session_id": session_id}
    )
    
    return {"message": "Logged out successfully"}

@router.post("/auth/change-password")
async def change_password(
    password_change: PasswordChange,
    current_user: dict = Depends(get_current_user)
):
    """Change user password."""
    user_id = current_user.get("id")
    if not user_id or user_id not in USERS:
        raise HTTPException(status_code=404, detail="User not found")
    
    user = USERS[user_id]
    
    # Verify current password
    if not verify_password(password_change.current_password, user.password_hash):
        await create_audit_log(
            user_id=user_id,
            username=user.username,
            action=AuditAction.UPDATE,
            resource_type="user_password",
            success=False,
            details={"reason": "invalid_current_password"}
        )
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Update password
    user.password_hash = hash_password(password_change.new_password)
    
    await create_audit_log(
        user_id=user_id,
        username=user.username,
        action=AuditAction.UPDATE,
        resource_type="user_password",
        details={"password_changed": True}
    )
    
    return {"message": "Password changed successfully"}

# ============================================================================
# Audit Logs
# ============================================================================

@router.get("/audit/logs", response_model=List[AuditLog])
async def get_audit_logs(
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    action: Optional[AuditAction] = Query(None, description="Filter by action"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    start_date: Optional[datetime] = Query(None, description="Start date filter"),
    end_date: Optional[datetime] = Query(None, description="End date filter"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of logs"),
    offset: int = Query(0, ge=0, description="Offset for pagination")
):
    """Get audit logs with filtering and pagination."""
    logs = AUDIT_LOGS.copy()
    
    # Apply filters
    if user_id:
        logs = [log for log in logs if log.user_id == user_id]
    
    if action:
        logs = [log for log in logs if log.action == action]
    
    if resource_type:
        logs = [log for log in logs if log.resource_type == resource_type]
    
    if start_date:
        logs = [log for log in logs if log.timestamp >= start_date]
    
    if end_date:
        logs = [log for log in logs if log.timestamp <= end_date]
    
    # Sort by timestamp (newest first)
    logs.sort(key=lambda x: x.timestamp, reverse=True)
    
    # Apply pagination
    return logs[offset:offset + limit]

@router.get("/audit/summary")
async def get_audit_summary():
    """Get audit log summary statistics."""
    total_logs = len(AUDIT_LOGS)
    
    # Count by action
    action_counts = {}
    for log in AUDIT_LOGS:
        action_counts[log.action] = action_counts.get(log.action, 0) + 1
    
    # Count by user
    user_counts = {}
    for log in AUDIT_LOGS:
        if log.user_id:
            user_counts[log.user_id] = user_counts.get(log.user_id, 0) + 1
    
    # Recent activity (last 24 hours)
    recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_logs = [log for log in AUDIT_LOGS if log.timestamp >= recent_cutoff]
    
    return {
        "total_logs": total_logs,
        "recent_activity_count": len(recent_logs),
        "action_breakdown": action_counts,
        "most_active_users": dict(sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:5])
    }

# ============================================================================
# Session Management
# ============================================================================

@router.get("/sessions", response_model=List[UserSession])
async def list_active_sessions():
    """List all active user sessions."""
    return list(ACTIVE_SESSIONS.values())

@router.delete("/sessions/{session_id}")
async def terminate_session(session_id: str, current_user: dict = Depends(get_current_user)):
    """Terminate a user session."""
    if session_id not in ACTIVE_SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = ACTIVE_SESSIONS.pop(session_id)
    
    await create_audit_log(
        user_id=current_user.get("id"),
        username=current_user.get("username"),
        action=AuditAction.DELETE,
        resource_type="session",
        resource_id=session_id,
        details={"terminated_user": session.username}
    )
    
    return {"message": "Session terminated successfully"}