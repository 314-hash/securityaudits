"""
Access Control Analyzer module for analyzing access control patterns and permissions in smart contracts.
"""

from typing import Dict, List, Any
from web3 import Web3
import logging

class AccessControlAnalyzer:
    """
    Analyzes access control patterns and permissions in smart contracts.
    """

    def __init__(self, web3_provider: str = None):
        self.logger = logging.getLogger(__name__)
        self.w3 = Web3(Web3.HTTPProvider(web3_provider)) if web3_provider else None

        # Access control patterns
        self.access_patterns = {
            "HIGH_RISK": {
                "unrestricted_access": {
                    "pattern": "public",
                    "description": "Unrestricted public access to sensitive functions"
                },
                "centralized_control": {
                    "pattern": "onlyOwner",
                    "description": "Highly centralized control mechanisms"
                },
                "privileged_roles": {
                    "pattern": "onlyRole",
                    "description": "Privileged role assignments without proper checks"
                }
            },
            "MEDIUM_RISK": {
                "role_management": {
                    "pattern": "grantRole",
                    "description": "Role management without proper validation"
                },
                "permission_delegation": {
                    "pattern": "delegatecall",
                    "description": "Permission delegation risks"
                },
                "access_modifiers": {
                    "pattern": "modifier",
                    "description": "Custom access modifiers without proper validation"
                }
            }
        }

    def analyze_access_control(self, contract_address: str) -> Dict[str, Any]:
        """
        Analyze access control patterns in a smart contract
        """
        if not self.w3 or not Web3.is_address(contract_address):
            return {"error": "Invalid contract address or web3 provider not configured"}

        findings = {
            "address": contract_address,
            "risk_level": "LOW",
            "access_issues": [],
            "recommendations": []
        }

        try:
            # Get contract code
            code = self.w3.eth.get_code(contract_address)
            if code == b'':
                return {"error": "Contract not found or not deployed"}

            # Analyze contract code for access control patterns
            findings.update(self._analyze_patterns(code))

        except Exception as e:
            self.logger.error(f"Error analyzing contract {contract_address}: {str(e)}")
            return {"error": f"Error analyzing contract: {str(e)}"}

        return findings

    def _analyze_patterns(self, contract_code: bytes) -> Dict[str, Any]:
        """
        Analyze contract code for access control patterns
        """
        findings = {
            "access_issues": [],
            "risk_level": "LOW",
            "recommendations": []
        }

        code_str = contract_code.hex().lower()

        # Check for high-risk patterns
        for pattern_name, pattern_info in self.access_patterns["HIGH_RISK"].items():
            if self._check_access_pattern(code_str, pattern_info["pattern"]):
                findings["access_issues"].append({
                    "type": pattern_name,
                    "description": pattern_info["description"],
                    "severity": "HIGH"
                })
                findings["risk_level"] = "HIGH"

        # Check for medium-risk patterns
        if findings["risk_level"] != "HIGH":
            for pattern_name, pattern_info in self.access_patterns["MEDIUM_RISK"].items():
                if self._check_access_pattern(code_str, pattern_info["pattern"]):
                    findings["access_issues"].append({
                        "type": pattern_name,
                        "description": pattern_info["description"],
                        "severity": "MEDIUM"
                    })
                    findings["risk_level"] = "MEDIUM"

        # Generate recommendations
        findings["recommendations"] = self._generate_recommendations(findings["access_issues"])
        return findings

    def _check_access_pattern(self, code: str, pattern: str) -> bool:
        """
        Check if an access control pattern exists in the contract code
        """
        return pattern.lower() in code

    def _generate_recommendations(self, issues: List[Dict[str, str]]) -> List[str]:
        """
        Generate recommendations for access control issues
        """
        recommendations = []
        for issue in issues:
            if issue["type"] == "unrestricted_access":
                recommendations.extend([
                    "Implement proper access control modifiers",
                    "Use OpenZeppelin's AccessControl contract",
                    "Add role-based access control (RBAC)"
                ])
            elif issue["type"] == "centralized_control":
                recommendations.extend([
                    "Implement multi-signature mechanisms",
                    "Add time-locks for critical operations",
                    "Consider implementing DAO governance"
                ])
            elif issue["type"] == "privileged_roles":
                recommendations.extend([
                    "Implement proper role validation",
                    "Add role hierarchy",
                    "Use time-delayed role assignments"
                ])
            elif issue["type"] == "role_management":
                recommendations.extend([
                    "Add proper role validation checks",
                    "Implement role revocation mechanisms",
                    "Use event logging for role changes"
                ])
            elif issue["type"] == "permission_delegation":
                recommendations.extend([
                    "Implement proper delegation controls",
                    "Add validation for delegated calls",
                    "Use proxy patterns for upgrades"
                ])
            elif issue["type"] == "access_modifiers":
                recommendations.extend([
                    "Review and test custom modifiers",
                    "Add proper validation checks",
                    "Use standardized access control patterns"
                ])

        return list(set(recommendations))  # Remove duplicates
