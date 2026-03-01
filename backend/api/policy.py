"""
Policy Management API Endpoints for the Adaptive LLM Firewall.

Provides endpoints for:
- Policy CRUD operations (Create, Read, Update, Delete)
- Policy templates and rule management
- Policy validation and testing
- Policy deployment and rollback
- Compliance reporting
"""

import logging
import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field

from api.db import log_event
from api.event_emitter import emit_event

logger = logging.getLogger(__name__)

router = APIRouter(tags=["policy"])

# In-memory policy store (replace with database in production)
POLICIES = {}
POLICY_TEMPLATES = {
    "basic_security": {
        "name": "Basic Security Policy",
        "description": "Standard security controls for LLM interactions",
        "rules": [
            {"type": "prompt_injection", "threshold": 0.7, "action": "block"},
            {"type": "data_leakage", "threshold": 0.8, "action": "quarantine"},
            {"type": "malicious_content", "threshold": 0.6, "action": "flag"}
        ]
    },
    "enterprise": {
        "name": "Enterprise Security Policy",
        "description": "Comprehensive security for enterprise environments",
        "rules": [
            {"type": "prompt_injection", "threshold": 0.5, "action": "block"},
            {"type": "data_leakage", "threshold": 0.6, "action": "block"},
            {"type": "malicious_content", "threshold": 0.4, "action": "quarantine"},
            {"type": "pii_detection", "threshold": 0.7, "action": "redact"},
            {"type": "compliance_check", "threshold": 0.9, "action": "audit"}
        ]
    },
    "development": {
        "name": "Development Policy",
        "description": "Lenient policy for development environments",
        "rules": [
            {"type": "prompt_injection", "threshold": 0.9, "action": "log"},
            {"type": "data_leakage", "threshold": 0.9, "action": "warn"},
            {"type": "malicious_content", "threshold": 0.8, "action": "log"}
        ]
    }
}

# ============================================================================
# Request / Response Models
# ============================================================================

class PolicyRule(BaseModel):
    """Individual policy rule definition."""
    type: str = Field(..., description="Rule type (e.g., 'prompt_injection', 'data_leakage')")
    threshold: float = Field(..., ge=0.0, le=1.0, description="Threshold value between 0 and 1")
    action: str = Field(..., description="Action to take (block, quarantine, flag, log, warn, redact, audit)")
    enabled: bool = Field(default=True, description="Whether the rule is active")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional rule configuration")

class Policy(BaseModel):
    """Policy definition with rules and metadata."""
    id: Optional[str] = Field(default=None, description="Policy ID (auto-generated if not provided)")
    name: str = Field(..., description="Policy name")
    description: str = Field(default="", description="Policy description")
    version: str = Field(default="1.0", description="Policy version")
    rules: List[PolicyRule] = Field(..., description="List of policy rules")
    enabled: bool = Field(default=True, description="Whether the policy is active")
    priority: int = Field(default=100, description="Policy priority (lower = higher priority)")
    tags: List[str] = Field(default_factory=list, description="Policy tags for organization")
    created_at: Optional[datetime] = Field(default=None, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(default=None, description="Last update timestamp")
    created_by: str = Field(default="system", description="Creator identifier")

class PolicyTestRequest(BaseModel):
    """Request for testing a policy against sample input."""
    policy_id: str
    test_input: str
    context: Dict[str, Any] = Field(default_factory=dict)

class PolicyTestResult(BaseModel):
    """Result of policy testing."""
    policy_id: str
    test_input: str
    triggered_rules: List[Dict[str, Any]]
    final_action: str
    score: float
    execution_time_ms: float

class ComplianceReport(BaseModel):
    """Compliance reporting data."""
    policy_id: str
    policy_name: str
    compliance_score: float
    violations_count: int
    last_violation: Optional[datetime]
    recommendations: List[str]

# ============================================================================
# Policy CRUD Operations
# ============================================================================

@router.get("/policies", response_model=List[Policy])
async def list_policies(
    enabled_only: bool = Query(False, description="Only return enabled policies"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of policies to return")
):
    """List all policies with optional filtering."""
    policies = list(POLICIES.values())
    
    if enabled_only:
        policies = [p for p in policies if p.enabled]
    
    if tag:
        policies = [p for p in policies if tag in p.tags]
    
    # Sort by priority (lower = higher priority)
    policies.sort(key=lambda p: p.priority)
    
    return policies[:limit]

@router.get("/policies/{policy_id}", response_model=Policy)
async def get_policy(policy_id: str):
    """Get a specific policy by ID."""
    if policy_id not in POLICIES:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    return POLICIES[policy_id]

@router.post("/policies", response_model=Policy, status_code=201)
async def create_policy(policy: Policy):
    """Create a new policy."""
    if policy.id is None:
        policy.id = str(uuid4())
    
    if policy.id in POLICIES:
        raise HTTPException(status_code=400, detail="Policy ID already exists")
    
    now = datetime.now(timezone.utc)
    policy.created_at = now
    policy.updated_at = now
    
    POLICIES[policy.id] = policy
    
    # Log the policy creation
    await log_event({
        "event_type": "policy_created",
        "policy_id": policy.id,
        "policy_name": policy.name,
        "created_by": policy.created_by,
        "timestamp": now.isoformat()
    })
    
    emit_event("policy_created", {
        "policy_id": policy.id,
        "policy_name": policy.name,
        "created_by": policy.created_by
    })
    
    return policy

@router.put("/policies/{policy_id}", response_model=Policy)
async def update_policy(policy_id: str, policy_update: Policy):
    """Update an existing policy."""
    if policy_id not in POLICIES:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    existing_policy = POLICIES[policy_id]
    
    # Preserve creation data and update timestamps
    policy_update.id = policy_id
    policy_update.created_at = existing_policy.created_at
    policy_update.updated_at = datetime.now(timezone.utc)
    
    POLICIES[policy_id] = policy_update
    
    # Log the policy update
    await log_event({
        "event_type": "policy_updated",
        "policy_id": policy_id,
        "policy_name": policy_update.name,
        "timestamp": policy_update.updated_at.isoformat()
    })
    
    emit_event("policy_updated", {
        "policy_id": policy_id,
        "policy_name": policy_update.name
    })
    
    return policy_update

@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: str):
    """Delete a policy."""
    if policy_id not in POLICIES:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    deleted_policy = POLICIES.pop(policy_id)
    
    # Log the policy deletion
    await log_event({
        "event_type": "policy_deleted",
        "policy_id": policy_id,
        "policy_name": deleted_policy.name,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    emit_event("policy_deleted", {
        "policy_id": policy_id,
        "policy_name": deleted_policy.name
    })
    
    return {"message": "Policy deleted successfully"}

# ============================================================================
# Policy Templates
# ============================================================================

@router.get("/policies/templates/list")
async def list_policy_templates():
    """List available policy templates."""
    return {
        "templates": [
            {"id": key, **template} 
            for key, template in POLICY_TEMPLATES.items()
        ]
    }

@router.post("/policies/from-template/{template_id}", response_model=Policy, status_code=201)
async def create_policy_from_template(
    template_id: str, 
    name: str = Query(..., description="Name for the new policy"),
    description: str = Query("", description="Description for the new policy")
):
    """Create a new policy from a template."""
    if template_id not in POLICY_TEMPLATES:
        raise HTTPException(status_code=404, detail="Template not found")
    
    template = POLICY_TEMPLATES[template_id]
    
    policy = Policy(
        name=name,
        description=description or template["description"],
        rules=[PolicyRule(**rule) for rule in template["rules"]],
        tags=[template_id, "template"]
    )
    
    return await create_policy(policy)

# ============================================================================
# Policy Testing and Validation
# ============================================================================

@router.post("/policies/test", response_model=PolicyTestResult)
async def test_policy(test_request: PolicyTestRequest):
    """Test a policy against sample input."""
    if test_request.policy_id not in POLICIES:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    policy = POLICIES[test_request.policy_id]
    start_time = datetime.now()
    
    triggered_rules = []
    final_action = "allow"
    max_score = 0.0
    
    # Simulate policy evaluation (replace with actual classifier calls)
    for rule in policy.rules:
        if not rule.enabled:
            continue
            
        # Mock rule evaluation - in reality, call appropriate classifiers
        score = simulate_rule_evaluation(rule.type, test_request.test_input)
        
        if score >= rule.threshold:
            triggered_rules.append({
                "rule_type": rule.type,
                "score": score,
                "threshold": rule.threshold,
                "action": rule.action
            })
            
            # Determine final action based on severity
            if rule.action in ["block"] and final_action != "block":
                final_action = rule.action
            elif rule.action in ["quarantine"] and final_action not in ["block"]:
                final_action = rule.action
                
            max_score = max(max_score, score)
    
    execution_time = (datetime.now() - start_time).total_seconds() * 1000
    
    return PolicyTestResult(
        policy_id=test_request.policy_id,
        test_input=test_request.test_input,
        triggered_rules=triggered_rules,
        final_action=final_action,
        score=max_score,
        execution_time_ms=execution_time
    )

@router.post("/policies/{policy_id}/enable")
async def enable_policy(policy_id: str):
    """Enable a policy."""
    if policy_id not in POLICIES:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    POLICIES[policy_id].enabled = True
    POLICIES[policy_id].updated_at = datetime.now(timezone.utc)
    
    emit_event("policy_enabled", {"policy_id": policy_id})
    return {"message": "Policy enabled"}

@router.post("/policies/{policy_id}/disable")
async def disable_policy(policy_id: str):
    """Disable a policy."""
    if policy_id not in POLICIES:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    POLICIES[policy_id].enabled = False
    POLICIES[policy_id].updated_at = datetime.now(timezone.utc)
    
    emit_event("policy_disabled", {"policy_id": policy_id})
    return {"message": "Policy disabled"}

# ============================================================================
# Compliance and Reporting
# ============================================================================

@router.get("/policies/compliance/report", response_model=List[ComplianceReport])
async def get_compliance_report():
    """Generate compliance report for all policies."""
    reports = []
    
    for policy_id, policy in POLICIES.items():
        # Mock compliance calculation (replace with real data)
        violations_count = len([r for r in policy.rules if not r.enabled])  # Simplified
        compliance_score = max(0.0, 1.0 - (violations_count * 0.1))
        
        recommendations = []
        if compliance_score < 0.8:
            recommendations.append("Consider enabling more security rules")
        if any(r.threshold > 0.8 for r in policy.rules):
            recommendations.append("Some thresholds may be too high")
        
        reports.append(ComplianceReport(
            policy_id=policy_id,
            policy_name=policy.name,
            compliance_score=compliance_score,
            violations_count=violations_count,
            last_violation=None,  # Would come from actual logs
            recommendations=recommendations
        ))
    
    return reports

# ============================================================================
# Helper Functions
# ============================================================================

def simulate_rule_evaluation(rule_type: str, input_text: str) -> float:
    """Simulate rule evaluation for testing purposes."""
    # This would be replaced with actual classifier calls
    suspicious_keywords = {
        "prompt_injection": ["ignore", "system", "admin", "bypass"],
        "data_leakage": ["password", "key", "secret", "token"],
        "malicious_content": ["hack", "exploit", "malware", "virus"]
    }
    
    keywords = suspicious_keywords.get(rule_type, [])
    score = sum(1 for keyword in keywords if keyword.lower() in input_text.lower()) / max(len(keywords), 1)
    return min(score, 1.0)

# Initialize with some default policies
def initialize_default_policies():
    """Initialize the system with default policies."""
    if not POLICIES:  # Only initialize if empty
        default_policy = Policy(
            id="default-security",
            name="Default Security Policy",
            description="Standard security policy for all interactions",
            rules=[
                PolicyRule(type="prompt_injection", threshold=0.7, action="block"),
                PolicyRule(type="data_leakage", threshold=0.8, action="quarantine"),
                PolicyRule(type="malicious_content", threshold=0.6, action="flag")
            ],
            tags=["default", "security"],
            created_by="system"
        )
        default_policy.created_at = datetime.now(timezone.utc)
        default_policy.updated_at = default_policy.created_at
        POLICIES[default_policy.id] = default_policy

# Initialize default policies on module load
initialize_default_policies()