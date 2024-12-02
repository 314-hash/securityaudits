"""
SignatureAnalyzer module for analyzing smart contract function signatures.
"""

import logging
from collections import defaultdict
from typing import Dict, List, Any

class SignatureAnalyzer:
    """
    Analyzes smart contract function signatures for potential security risks.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # High-risk patterns that indicate potential security vulnerabilities
        self.high_risk_patterns = {
            "delegatecall": "Dangerous delegatecall operation",
            "selfdestruct": "Contract self-destruct capability",
            "suicide": "Deprecated self-destruct operation",
            "raw": "Low-level operation",
            "assembly": "Assembly code usage",
            "ecrecover": "Signature recovery - check for replay attacks",
            "transferownership": "Administrative ownership transfer"
        }

        # Medium-risk patterns that require careful review
        self.medium_risk_patterns = {
            "transfer": "Function may handle token or Ether transfers",
            "send": "Low-level Ether transfer function",
            "call": "Low-level external call",
            "owner": "Administrative function",
            "admin": "Administrative function",
            "upgrade": "Contract upgrade capability",
            "pause": "Contract pausability",
            "blacklist": "Address blacklisting capability",
            "whitelist": "Address whitelisting capability",
            "approve": "Token approval function",
            "increase": "Value modification function",
            "decrease": "Value modification function",
            "withdraw": "Asset withdrawal function",
            "deposit": "Asset deposit function",
            "timelock": "Time-dependent operation",
            "delay": "Time-dependent operation",
            "oracle": "Oracle integration",
            "random": "Randomness source - check implementation",
            "callback": "Callback function - check reentrancy",
            "external": "External contract interaction",
            "_fallback": "Fallback function - handle with care",
            "receive": "Ether receiving function",
            "setadmin": "Administrative function",
            "mint": "Token minting capability",
            "burn": "Token burning capability"
        }

    def _analyze_single_signature(self, signature: str) -> Dict[str, Any]:
        """
        Analyze a single function signature for security patterns
        """
        findings = {
            "signature": signature,
            "risk_level": "LOW",
            "risks": [],
            "description": []
        }

        # Extract function name without parameters and convert to lowercase for comparison
        func_name = signature.lower().split("(")[0].strip()

        # First pass: Check for high-risk patterns
        for pattern, desc in self.high_risk_patterns.items():
            pattern_lower = pattern.lower()
            # Check for word boundaries to avoid partial matches
            if pattern_lower in func_name.split("_"):
                findings["risks"].append(pattern)
                findings["description"].append(desc)
                findings["risk_level"] = "HIGH"

        # Second pass: Check for medium-risk patterns
        # We'll check these even if we found high risks to get comprehensive findings
        for pattern, desc in self.medium_risk_patterns.items():
            pattern_lower = pattern.lower()
            # Check for word boundaries to avoid partial matches
            if pattern_lower in func_name.split("_") and pattern not in findings["risks"]:
                findings["risks"].append(pattern)
                findings["description"].append(desc)
                if findings["risk_level"] != "HIGH":
                    findings["risk_level"] = "MEDIUM"

        return findings

    def analyze_signatures(self, signatures: List[str]) -> Dict[str, Any]:
        """
        Analyze a list of function signatures for security risks
        """
        results = {
            "risk_level": "LOW",
            "findings": [],
            "statistics": defaultdict(int),
            "recommendations": []
        }

        # Analyze each signature
        for sig in signatures:
            findings = self._analyze_single_signature(sig)
            results["findings"].append(findings)
            results["statistics"][findings["risk_level"]] += 1

        # Update total count
        results["statistics"]["total"] = len(signatures)

        # Set overall risk level based on statistics
        if results["statistics"]["HIGH"] > 0:
            results["risk_level"] = "HIGH"
        elif results["statistics"]["MEDIUM"] > 0:
            results["risk_level"] = "MEDIUM"

        # Generate recommendations
        results["recommendations"] = self._generate_recommendations(results["findings"])
        return results

    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """
        Generate security recommendations based on findings
        """
        recommendations = []
        risk_counts = defaultdict(int)

        # Count occurrences of each risk pattern
        for finding in findings:
            for risk in finding["risks"]:
                risk_counts[risk.lower()] += 1

        # Generate recommendations for each risk pattern
        for risk, count in risk_counts.items():
            risk_lower = risk.lower()
            if risk_lower in ["delegatecall", "call"]:
                recommendations.append(
                    f"Found {count} instances of {risk}: Implement proper access controls and input validation"
                )
            elif risk_lower in ["selfdestruct", "suicide"]:
                recommendations.append(
                    f"Found {count} instances of {risk}: Ensure strong access controls and consider removing if not necessary"
                )
            elif risk_lower in ["transfer", "send"]:
                recommendations.append(
                    f"Found {count} instances of {risk}: Check for reentrancy and handle transfer failures properly"
                )
            elif risk_lower in ["owner", "admin", "transferownership", "setadmin"]:
                recommendations.append(
                    f"Found {count} administrative functions: Implement multi-signature or timelock mechanisms"
                )
            elif risk_lower == "mint":
                recommendations.append(
                    f"Found {count} token minting functions: Ensure proper access controls and supply caps"
                )
            elif risk_lower == "burn":
                recommendations.append(
                    f"Found {count} token burning functions: Ensure proper access controls and validation"
                )
            elif risk_lower in ["withdraw", "deposit"]:
                recommendations.append(
                    f"Found {count} asset management functions: Implement proper access controls and input validation"
                )
            elif risk_lower in ["approve", "increase", "decrease"]:
                recommendations.append(
                    f"Found {count} value modification functions: Check for proper authorization and value validation"
                )
            elif risk_lower in ["oracle", "random"]:
                recommendations.append(
                    f"Found {count} external data dependency functions: Ensure proper data validation and fallback mechanisms"
                )
            elif risk_lower in ["callback"]:
                recommendations.append(
                    f"Found {count} callback functions: Check for reentrancy vulnerabilities"
                )
            elif risk_lower in ["timelock", "delay"]:
                recommendations.append(
                    f"Found {count} time-dependent operations: Validate timestamp manipulation resistance"
                )
            else:
                recommendations.append(
                    f"Found {count} instances of {risk}: Review for potential security implications"
                )

        return list(set(recommendations))  # Remove any duplicate recommendations
