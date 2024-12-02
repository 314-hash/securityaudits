import pytest
from audit_tools.signature_analyzer import SignatureAnalyzer

@pytest.fixture
def analyzer():
    return SignatureAnalyzer()

def test_analyze_signatures_high_risk(analyzer):
    signatures = [
        "transferOwnership(address)",
        "delegatecall(bytes)",
        "selfdestruct(address)",
        "mint(address,uint256)"
    ]
    results = analyzer.analyze_signatures(signatures)
    assert results["risk_level"] == "HIGH"
    assert results["statistics"]["HIGH"] >= 3

def test_analyze_signatures_medium_risk(analyzer):
    signatures = [
        "approve(address,uint256)",
        "withdraw(uint256)",
        "setAdmin(address)",
        "deposit()"
    ]
    results = analyzer.analyze_signatures(signatures)
    assert results["risk_level"] == "MEDIUM"

def test_analyze_signatures_low_risk(analyzer):
    signatures = [
        "name()",
        "symbol()",
        "decimals()",
        "totalSupply()"
    ]
    results = analyzer.analyze_signatures(signatures)
    assert results["risk_level"] == "LOW"

def test_analyze_single_signature_high_risk(analyzer):
    signature = "delegatecall(bytes)"
    result = analyzer._analyze_single_signature(signature)
    assert result["risk_level"] == "HIGH"

def test_analyze_single_signature_medium_risk(analyzer):
    signature = "withdraw(uint256)"
    result = analyzer._analyze_single_signature(signature)
    assert result["risk_level"] == "MEDIUM"

def test_analyze_single_signature_low_risk(analyzer):
    signature = "name()"
    result = analyzer._analyze_single_signature(signature)
    assert result["risk_level"] == "LOW"

def test_generate_recommendations(analyzer):
    signatures = [
        "delegatecall(bytes)",
        "withdraw(uint256)",
        "transferOwnership(address)"
    ]
    results = analyzer.analyze_signatures(signatures)
    assert len(results["recommendations"]) > 0

def test_mixed_risk_levels(analyzer):
    signatures = [
        "delegatecall(bytes)",  # HIGH
        "withdraw(uint256)",    # MEDIUM
        "name()"               # LOW
    ]
    results = analyzer.analyze_signatures(signatures)
    assert results["risk_level"] == "HIGH"
    assert results["statistics"]["HIGH"] == 1
    assert results["statistics"]["MEDIUM"] == 1
    assert results["statistics"]["LOW"] == 1

def test_multiple_risks_single_signature(analyzer):
    signature = "transferAndCallAndSelfDestruct(address,bytes)"
    result = analyzer._analyze_single_signature(signature)
    assert result["risk_level"] == "HIGH"
    assert len(result["risks"]) >= 2  # Should detect multiple risks

def test_case_insensitive_pattern_matching(analyzer):
    signatures = [
        "TRANSFEROWNERSHIP(address)",
        "DelegateCall(bytes)",
        "Mint(address,uint256)"
    ]
    results = analyzer.analyze_signatures(signatures)
    assert results["risk_level"] == "HIGH"
    assert results["statistics"]["HIGH"] >= 3
