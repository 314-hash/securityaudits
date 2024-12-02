"""
DeFi Scanner module for analyzing DeFi-specific security risks.
"""

from typing import Dict, List, Any
from web3 import Web3
import logging

class DeFiScanner:
    """
    Analyzes DeFi-specific security risks in smart contracts.
    """

    def __init__(self, web3_provider: str = None):
        self.logger = logging.getLogger(__name__)
        self.w3 = Web3(Web3.HTTPProvider(web3_provider)) if web3_provider else None
        
        # DeFi-specific risk patterns
        self.defi_risk_patterns = {
            "HIGH": {
                "flash_loan": "Flash loan vulnerability",
                "price_oracle": "Price oracle manipulation risk",
                "reentrancy": "Reentrancy vulnerability",
                "front_running": "Front-running vulnerability",
                "infinite_approval": "Infinite token approval risk",
                "sandwich_attack": "Sandwich attack vulnerability"
            },
            "MEDIUM": {
                "slippage": "Slippage control",
                "liquidity_pool": "Liquidity pool manipulation",
                "yield_farming": "Yield farming risks",
                "governance": "Governance manipulation",
                "token_inflation": "Token inflation risks"
            }
        }

    def scan_contract(self, contract_address: str) -> Dict[str, Any]:
        """
        Scan a DeFi contract for potential vulnerabilities
        """
        if not self.w3 or not Web3.is_address(contract_address):
            return {"error": "Invalid contract address or web3 provider not configured"}

        findings = {
            "address": contract_address,
            "risk_level": "LOW",
            "vulnerabilities": [],
            "recommendations": []
        }

        try:
            # Get contract code
            code = self.w3.eth.get_code(contract_address)
            if code == b'':
                return {"error": "Contract not found or not deployed"}

            # Analyze contract code for DeFi-specific risks
            findings.update(self._analyze_defi_risks(code))

        except Exception as e:
            self.logger.error(f"Error scanning contract {contract_address}: {str(e)}")
            return {"error": f"Error scanning contract: {str(e)}"}

        return findings

    def _analyze_defi_risks(self, contract_code: bytes) -> Dict[str, Any]:
        """
        Analyze contract code for DeFi-specific risks
        """
        findings = {
            "vulnerabilities": [],
            "risk_level": "LOW",
            "recommendations": []
        }

        code_str = contract_code.hex().lower()

        # Check for high-risk patterns
        for pattern, desc in self.defi_risk_patterns["HIGH"].items():
            if self._check_pattern(code_str, pattern):
                findings["vulnerabilities"].append({
                    "type": pattern,
                    "description": desc,
                    "severity": "HIGH"
                })
                findings["risk_level"] = "HIGH"

        # Check for medium-risk patterns if no high risks found
        if findings["risk_level"] != "HIGH":
            for pattern, desc in self.defi_risk_patterns["MEDIUM"].items():
                if self._check_pattern(code_str, pattern):
                    findings["vulnerabilities"].append({
                        "type": pattern,
                        "description": desc,
                        "severity": "MEDIUM"
                    })
                    findings["risk_level"] = "MEDIUM"

        # Generate recommendations
        findings["recommendations"] = self._generate_defi_recommendations(findings["vulnerabilities"])
        return findings

    def _check_pattern(self, code: str, pattern: str) -> bool:
        """
        Check if a pattern exists in the contract code
        """
        return pattern.lower().replace("_", "") in code

    def _generate_defi_recommendations(self, vulnerabilities: List[Dict[str, str]]) -> List[str]:
        """
        Generate DeFi-specific security recommendations
        """
        recommendations = []
        for vuln in vulnerabilities:
            if vuln["type"] == "flash_loan":
                recommendations.append(
                    "Implement proper validation and access controls for flash loan functions"
                )
            elif vuln["type"] == "price_oracle":
                recommendations.append(
                    "Use multiple price oracles and implement proper validation mechanisms"
                )
            elif vuln["type"] == "reentrancy":
                recommendations.append(
                    "Implement reentrancy guards and follow checks-effects-interactions pattern"
                )
            elif vuln["type"] == "front_running":
                recommendations.append(
                    "Implement commit-reveal schemes or use flash-bots to prevent front-running"
                )
            elif vuln["type"] == "infinite_approval":
                recommendations.append(
                    "Implement token approval limits and expiration mechanisms"
                )
            elif vuln["type"] == "sandwich_attack":
                recommendations.append(
                    "Implement slippage protection and minimum output amounts"
                )
            elif vuln["type"] == "slippage":
                recommendations.append(
                    "Add configurable slippage parameters and deadline checks"
                )
            elif vuln["type"] == "liquidity_pool":
                recommendations.append(
                    "Implement proper liquidity pool validation and manipulation checks"
                )
            elif vuln["type"] == "yield_farming":
                recommendations.append(
                    "Add harvest lockup periods and implement proper reward distribution checks"
                )
            elif vuln["type"] == "governance":
                recommendations.append(
                    "Implement timelock mechanisms and proper voting power calculations"
                )
            elif vuln["type"] == "token_inflation":
                recommendations.append(
                    "Implement proper minting controls and supply caps"
                )

        return list(set(recommendations))  # Remove duplicates
