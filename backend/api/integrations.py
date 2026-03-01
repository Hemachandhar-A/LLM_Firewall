"""
Integration Management API Endpoints for the Adaptive LLM Firewall.

Provides endpoints for:
- Third-party integrations (SIEM, monitoring tools, etc.)
- API key management
- Webhook configurations
- Integration health monitoring
- Data export/import capabilities
"""

import logging
import json
import asyncio
import aiohttp
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from uuid import uuid4
from enum import Enum

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field, validator

from api.db import log_event
from api.event_emitter import emit_event

logger = logging.getLogger(__name__)

router = APIRouter(tags=["integrations"])

# In-memory stores (replace with database in production)
INTEGRATIONS = {}
API_KEYS = {}
WEBHOOKS = {}

class IntegrationType(str, Enum):
    SIEM = "siem"
    MONITORING = "monitoring"
    TICKETING = "ticketing"
    NOTIFICATION = "notification"
    ANALYTICS = "analytics"
    THREAT_INTEL = "threat_intelligence"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"

class IntegrationStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"

class AuthType(str, Enum):
    API_KEY = "api_key"
    OAUTH = "oauth"
    BASIC = "basic_auth"
    BEARER_TOKEN = "bearer_token"
    CUSTOM = "custom"

# ============================================================================
# Request / Response Models
# ============================================================================

class IntegrationAuth(BaseModel):
    """Authentication configuration for integrations."""
    type: AuthType
    credentials: Dict[str, str] = Field(..., description="Encrypted credentials")
    headers: Dict[str, str] = Field(default_factory=dict, description="Additional headers")

class Integration(BaseModel):
    """Integration configuration."""
    id: Optional[str] = Field(default=None, description="Integration ID")
    name: str = Field(..., description="Integration name")
    type: IntegrationType = Field(..., description="Integration type")
    description: str = Field(default="", description="Integration description")
    endpoint: str = Field(..., description="Integration endpoint URL")
    auth: IntegrationAuth = Field(..., description="Authentication configuration")
    config: Dict[str, Any] = Field(default_factory=dict, description="Integration-specific configuration")
    enabled: bool = Field(default=True, description="Whether the integration is active")
    status: IntegrationStatus = Field(default=IntegrationStatus.PENDING, description="Current status")
    last_sync: Optional[datetime] = Field(default=None, description="Last successful sync")
    error_count: int = Field(default=0, description="Number of consecutive errors")
    created_at: Optional[datetime] = Field(default=None, description="Creation timestamp")
    created_by: str = Field(default="system", description="Creator identifier")
    tags: List[str] = Field(default_factory=list, description="Integration tags")

class APIKey(BaseModel):
    """API key for external access."""
    id: Optional[str] = Field(default=None, description="API key ID")
    name: str = Field(..., description="API key name")
    key_hash: str = Field(..., description="Hashed API key")
    key_prefix: str = Field(..., description="API key prefix for identification")
    permissions: List[str] = Field(..., description="Granted permissions")
    rate_limit: int = Field(default=1000, description="Requests per hour")
    ip_whitelist: List[str] = Field(default_factory=list, description="Allowed IP addresses")
    expires_at: Optional[datetime] = Field(default=None, description="Expiration date")
    last_used: Optional[datetime] = Field(default=None, description="Last usage timestamp")
    usage_count: int = Field(default=0, description="Total usage count")
    created_at: Optional[datetime] = Field(default=None, description="Creation timestamp")
    created_by: str = Field(default="system", description="Creator identifier")
    enabled: bool = Field(default=True, description="Whether the key is active")

class Webhook(BaseModel):
    """Webhook configuration."""
    id: Optional[str] = Field(default=None, description="Webhook ID")
    name: str = Field(..., description="Webhook name")
    url: str = Field(..., description="Webhook URL")
    events: List[str] = Field(..., description="Events to trigger webhook")
    secret: Optional[str] = Field(default=None, description="Webhook secret for verification")
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom headers")
    enabled: bool = Field(default=True, description="Whether the webhook is active")
    retry_count: int = Field(default=3, description="Number of retry attempts")
    timeout: int = Field(default=30, description="Timeout in seconds")
    last_delivery: Optional[datetime] = Field(default=None, description="Last successful delivery")
    failure_count: int = Field(default=0, description="Consecutive failure count")
    created_at: Optional[datetime] = Field(default=None, description="Creation timestamp")

class WebhookDelivery(BaseModel):
    """Webhook delivery information."""
    webhook_id: str
    event_type: str
    payload: Dict[str, Any]
    delivered_at: datetime
    status_code: int
    response_body: str
    attempt_number: int

class IntegrationTest(BaseModel):
    """Integration test configuration."""
    integration_id: str
    test_data: Dict[str, Any] = Field(default_factory=dict)

class DataExportRequest(BaseModel):
    """Data export request."""
    format: str = Field(..., description="Export format (json, csv, xml)")
    date_from: Optional[datetime] = Field(default=None, description="Start date")
    date_to: Optional[datetime] = Field(default=None, description="End date")
    filters: Dict[str, Any] = Field(default_factory=dict, description="Additional filters")

# ============================================================================
# Integration Management
# ============================================================================

@router.get("/integrations", response_model=List[Integration])
async def list_integrations(
    type: Optional[IntegrationType] = Query(None, description="Filter by integration type"),
    status: Optional[IntegrationStatus] = Query(None, description="Filter by status"),
    enabled_only: bool = Query(False, description="Only return enabled integrations")
):
    """List all integrations with optional filtering."""
    integrations = list(INTEGRATIONS.values())
    
    if type:
        integrations = [i for i in integrations if i.type == type]
    
    if status:
        integrations = [i for i in integrations if i.status == status]
    
    if enabled_only:
        integrations = [i for i in integrations if i.enabled]
    
    return integrations

@router.get("/integrations/{integration_id}", response_model=Integration)
async def get_integration(integration_id: str):
    """Get a specific integration by ID."""
    if integration_id not in INTEGRATIONS:
        raise HTTPException(status_code=404, detail="Integration not found")
    
    return INTEGRATIONS[integration_id]

@router.post("/integrations", response_model=Integration, status_code=201)
async def create_integration(integration: Integration, background_tasks: BackgroundTasks):
    """Create a new integration."""
    if integration.id is None:
        integration.id = str(uuid4())
    
    if integration.id in INTEGRATIONS:
        raise HTTPException(status_code=400, detail="Integration ID already exists")
    
    now = datetime.now(timezone.utc)
    integration.created_at = now
    
    INTEGRATIONS[integration.id] = integration
    
    # Test the integration in the background
    background_tasks.add_task(test_integration_connectivity, integration.id)
    
    await log_event({
        "event_type": "integration_created",
        "integration_id": integration.id,
        "integration_name": integration.name,
        "integration_type": integration.type,
        "timestamp": now.isoformat()
    })
    
    emit_event("integration_created", {
        "integration_id": integration.id,
        "integration_name": integration.name,
        "integration_type": integration.type
    })
    
    return integration

@router.put("/integrations/{integration_id}", response_model=Integration)
async def update_integration(integration_id: str, integration_update: Integration):
    """Update an existing integration."""
    if integration_id not in INTEGRATIONS:
        raise HTTPException(status_code=404, detail="Integration not found")
    
    existing_integration = INTEGRATIONS[integration_id]
    
    integration_update.id = integration_id
    integration_update.created_at = existing_integration.created_at
    
    INTEGRATIONS[integration_id] = integration_update
    
    await log_event({
        "event_type": "integration_updated",
        "integration_id": integration_id,
        "integration_name": integration_update.name,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return integration_update

@router.delete("/integrations/{integration_id}")
async def delete_integration(integration_id: str):
    """Delete an integration."""
    if integration_id not in INTEGRATIONS:
        raise HTTPException(status_code=404, detail="Integration not found")
    
    deleted_integration = INTEGRATIONS.pop(integration_id)
    
    await log_event({
        "event_type": "integration_deleted",
        "integration_id": integration_id,
        "integration_name": deleted_integration.name,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return {"message": "Integration deleted successfully"}

@router.post("/integrations/{integration_id}/test")
async def test_integration(integration_id: str, test_config: Optional[IntegrationTest] = None):
    """Test an integration's connectivity."""
    if integration_id not in INTEGRATIONS:
        raise HTTPException(status_code=404, detail="Integration not found")
    
    integration = INTEGRATIONS[integration_id]
    
    try:
        result = await test_integration_connectivity(integration_id)
        return {
            "integration_id": integration_id,
            "status": "success" if result else "failed",
            "message": "Connection test completed",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        return {
            "integration_id": integration_id,
            "status": "failed",
            "message": f"Connection test failed: {str(e)}",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

# ============================================================================
# API Key Management
# ============================================================================

@router.get("/api-keys", response_model=List[APIKey])
async def list_api_keys(enabled_only: bool = Query(False)):
    """List all API keys (excluding the actual key values)."""
    keys = list(API_KEYS.values())
    
    if enabled_only:
        keys = [k for k in keys if k.enabled]
    
    # Remove sensitive information from response
    for key in keys:
        key.key_hash = "****"  # Don't expose hash in list
    
    return keys

@router.post("/api-keys", response_model=Dict[str, str], status_code=201)
async def create_api_key(
    name: str = Query(..., description="API key name"),
    permissions: List[str] = Query(..., description="Granted permissions"),
    expires_days: Optional[int] = Query(None, description="Expiration in days")
):
    """Create a new API key."""
    import secrets
    import hashlib
    
    # Generate API key
    key_value = f"sk-{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(key_value.encode()).hexdigest()
    key_prefix = key_value[:12]
    
    # Calculate expiration
    expires_at = None
    if expires_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
    
    api_key = APIKey(
        id=str(uuid4()),
        name=name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        permissions=permissions,
        expires_at=expires_at,
        created_at=datetime.now(timezone.utc)
    )
    
    API_KEYS[api_key.id] = api_key
    
    await log_event({
        "event_type": "api_key_created",
        "api_key_id": api_key.id,
        "api_key_name": name,
        "permissions": permissions,
        "timestamp": api_key.created_at.isoformat()
    })
    
    return {
        "api_key_id": api_key.id,
        "api_key": key_value,  # Only returned once!
        "message": "API key created successfully. Save this key - it won't be shown again."
    }

@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: str):
    """Revoke an API key."""
    if key_id not in API_KEYS:
        raise HTTPException(status_code=404, detail="API key not found")
    
    deleted_key = API_KEYS.pop(key_id)
    
    await log_event({
        "event_type": "api_key_revoked",
        "api_key_id": key_id,
        "api_key_name": deleted_key.name,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return {"message": "API key revoked successfully"}

# ============================================================================
# Webhook Management
# ============================================================================

@router.get("/webhooks", response_model=List[Webhook])
async def list_webhooks(enabled_only: bool = Query(False)):
    """List all webhooks."""
    webhooks = list(WEBHOOKS.values())
    
    if enabled_only:
        webhooks = [w for w in webhooks if w.enabled]
    
    return webhooks

@router.post("/webhooks", response_model=Webhook, status_code=201)
async def create_webhook(webhook: Webhook):
    """Create a new webhook."""
    if webhook.id is None:
        webhook.id = str(uuid4())
    
    if webhook.id in WEBHOOKS:
        raise HTTPException(status_code=400, detail="Webhook ID already exists")
    
    webhook.created_at = datetime.now(timezone.utc)
    WEBHOOKS[webhook.id] = webhook
    
    await log_event({
        "event_type": "webhook_created",
        "webhook_id": webhook.id,
        "webhook_name": webhook.name,
        "webhook_url": webhook.url,
        "timestamp": webhook.created_at.isoformat()
    })
    
    return webhook

@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str):
    """Delete a webhook."""
    if webhook_id not in WEBHOOKS:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    deleted_webhook = WEBHOOKS.pop(webhook_id)
    
    await log_event({
        "event_type": "webhook_deleted",
        "webhook_id": webhook_id,
        "webhook_name": deleted_webhook.name,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return {"message": "Webhook deleted successfully"}

# ============================================================================
# Data Export/Import
# ============================================================================

@router.post("/export/threats")
async def export_threat_data(export_request: DataExportRequest):
    """Export threat data in specified format."""
    # Mock export functionality
    data = {
        "export_id": str(uuid4()),
        "format": export_request.format,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "record_count": 1000,  # Mock count
        "download_url": f"/api/integrations/downloads/{str(uuid4())}.{export_request.format}"
    }
    
    await log_event({
        "event_type": "data_exported",
        "export_format": export_request.format,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return data

@router.get("/integrations/health")
async def get_integration_health():
    """Get health status of all integrations."""
    health_status = []
    
    for integration_id, integration in INTEGRATIONS.items():
        health_status.append({
            "integration_id": integration_id,
            "name": integration.name,
            "type": integration.type,
            "status": integration.status,
            "enabled": integration.enabled,
            "last_sync": integration.last_sync,
            "error_count": integration.error_count
        })
    
    return {
        "integrations": health_status,
        "total_count": len(INTEGRATIONS),
        "active_count": len([i for i in INTEGRATIONS.values() if i.enabled]),
        "error_count": len([i for i in INTEGRATIONS.values() if i.status == IntegrationStatus.ERROR])
    }

# ============================================================================
# Helper Functions
# ============================================================================

async def test_integration_connectivity(integration_id: str) -> bool:
    """Test connectivity to an integration."""
    if integration_id not in INTEGRATIONS:
        return False
    
    integration = INTEGRATIONS[integration_id]
    
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            headers = integration.auth.headers.copy()
            
            # Add authentication headers based on type
            if integration.auth.type == AuthType.API_KEY:
                headers["X-API-Key"] = integration.auth.credentials.get("api_key", "")
            elif integration.auth.type == AuthType.BEARER_TOKEN:
                headers["Authorization"] = f"Bearer {integration.auth.credentials.get('token', '')}"
            
            async with session.get(integration.endpoint, headers=headers) as response:
                success = response.status < 400
                integration.status = IntegrationStatus.ACTIVE if success else IntegrationStatus.ERROR
                
                if success:
                    integration.last_sync = datetime.now(timezone.utc)
                    integration.error_count = 0
                else:
                    integration.error_count += 1
                
                return success
                
    except Exception as e:
        logger.error(f"Integration test failed for {integration_id}: {e}")
        integration.status = IntegrationStatus.ERROR
        integration.error_count += 1
        return False

async def deliver_webhook(webhook_id: str, event_type: str, payload: Dict[str, Any]) -> WebhookDelivery:
    """Deliver a webhook notification."""
    if webhook_id not in WEBHOOKS:
        raise ValueError(f"Webhook {webhook_id} not found")
    
    webhook = WEBHOOKS[webhook_id]
    
    if not webhook.enabled or event_type not in webhook.events:
        return None
    
    delivery = WebhookDelivery(
        webhook_id=webhook_id,
        event_type=event_type,
        payload=payload,
        delivered_at=datetime.now(timezone.utc),
        status_code=0,
        response_body="",
        attempt_number=1
    )
    
    try:
        timeout = aiohttp.ClientTimeout(total=webhook.timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            headers = {"Content-Type": "application/json"}
            headers.update(webhook.headers)
            
            if webhook.secret:
                import hmac
                import hashlib
                signature = hmac.new(
                    webhook.secret.encode(),
                    json.dumps(payload).encode(),
                    hashlib.sha256
                ).hexdigest()
                headers["X-Webhook-Signature"] = f"sha256={signature}"
            
            async with session.post(webhook.url, json=payload, headers=headers) as response:
                delivery.status_code = response.status
                delivery.response_body = await response.text()
                
                if response.status < 400:
                    webhook.last_delivery = delivery.delivered_at
                    webhook.failure_count = 0
                else:
                    webhook.failure_count += 1
                
                return delivery
                
    except Exception as e:
        webhook.failure_count += 1
        delivery.status_code = 0
        delivery.response_body = str(e)
        return delivery

# Initialize some default integrations
def initialize_default_integrations():
    """Initialize with some example integrations."""
    if not INTEGRATIONS:  # Only initialize if empty
        # Example SIEM integration
        siem_integration = Integration(
            id="default-siem",
            name="Default SIEM Integration",
            type=IntegrationType.SIEM,
            description="Default SIEM integration for security events",
            endpoint="https://siem.company.com/api/events",
            auth=IntegrationAuth(
                type=AuthType.API_KEY,
                credentials={"api_key": "placeholder"},
                headers={"User-Agent": "Slingshot-Firewall/1.0"}
            ),
            config={"batch_size": 100, "retry_interval": 300},
            enabled=False,  # Disabled by default
            tags=["siem", "security"]
        )
        siem_integration.created_at = datetime.now(timezone.utc)
        INTEGRATIONS[siem_integration.id] = siem_integration

initialize_default_integrations()