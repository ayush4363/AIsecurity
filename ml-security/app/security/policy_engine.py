"""
The Possessed Butler - Independent Policy Engine
Enforces least-privilege tool execution permissions regardless of model predictions.
"""

from typing import Dict, Any

class PolicyEngine:
    def __init__(self):
        # Strict action permission matrix
        self.action_policies = {
            "READ_EMAIL": {"decision": "ALLOW", "requires_approval": False},
            "SUMMARIZE_CONTENT": {"decision": "ALLOW", "requires_approval": False},
            "DRAFT_EMAIL": {"decision": "ALLOW", "requires_approval": False},
            "SEND_EMAIL": {"decision": "REQUIRE_APPROVAL", "requires_approval": True},
            "DELETE_EMAIL": {"decision": "REQUIRE_APPROVAL", "requires_approval": True},
            "EDIT_FILE": {"decision": "REQUIRE_APPROVAL", "requires_approval": True},
            "DELETE_FILE": {"decision": "REQUIRE_APPROVAL", "requires_approval": True},
            "ACCESS_ENV_VARS": {"decision": "BLOCK", "requires_approval": False},
            "READ_APPLICATION_SECRETS": {"decision": "BLOCK", "requires_approval": False},
            "EXECUTE_SHELL": {"decision": "BLOCK", "requires_approval": False}
        }

    def evaluate_tool_request(self, action_type: str, parameters: Dict[str, Any] = None, prompt_tainted: bool = False) -> dict:
        policy = self.action_policies.get(action_type, {"decision": "BLOCK", "requires_approval": False})

        # RULE 1: If originating prompt was tainted by an injection or attack, block sensitive operations
        if prompt_tainted and policy["decision"] != "ALLOW":
            return {
                "decision": "BLOCK",
                "reason": f"Tainted Instruction Guard: Action '{action_type}' blocked because the input context contained adversarial directives.",
                "requires_approval": False,
                "is_authorized": False
            }

        # RULE 2: Prohibited Actions are unconditionally blocked
        if policy["decision"] == "BLOCK":
            return {
                "decision": "BLOCK",
                "reason": f"Least-Privilege Policy: Action '{action_type}' is strictly prohibited for AI agents.",
                "requires_approval": False,
                "is_authorized": False
            }

        # RULE 3: Sensitive Operations require Human Approval
        if policy["requires_approval"]:
            return {
                "decision": "REQUIRE_APPROVAL",
                "reason": f"Human-In-The-Loop Required: Action '{action_type}' is sensitive and requires explicit user confirmation.",
                "requires_approval": True,
                "is_authorized": False
            }

        # RULE 4: Clean read/draft actions are allowed
        return {
            "decision": "ALLOW",
            "reason": f"Action '{action_type}' verified clean under least-privilege policy.",
            "requires_approval": False,
            "is_authorized": True
        }

policy_engine = PolicyEngine()
