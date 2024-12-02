import pytest
from audit_tools.access_control_analyzer import AccessControlAnalyzer

@pytest.fixture
def analyzer():
    return AccessControlAnalyzer()

def test_analyze_access_control_invalid_address(analyzer):
    result = analyzer.analyze_access_control("0xinvalid")
    assert "error" in result

def test_analyze_patterns_high_risk(analyzer):
    # Simulate contract code with high-risk access patterns
    code = bytes.fromhex("7075626c6963")  # "public" in hex
    findings = analyzer._analyze_patterns(code)
    assert findings["risk_level"] == "HIGH"
    assert len(findings["access_issues"]) > 0

def test_analyze_patterns_medium_risk(analyzer):
    # Simulate contract code with medium-risk access patterns
    code = bytes.fromhex("6772616e74526f6c65")  # "grantRole" in hex
    findings = analyzer._analyze_patterns(code)
    assert findings["risk_level"] == "MEDIUM"
    assert len(findings["access_issues"]) > 0

def test_analyze_patterns_low_risk(analyzer):
    # Simulate contract code with no risk patterns
    code = bytes.fromhex("736166655f636f6465")  # "safe_code" in hex
    findings = analyzer._analyze_patterns(code)
    assert findings["risk_level"] == "LOW"
    assert len(findings["access_issues"]) == 0

def test_check_access_pattern(analyzer):
    code = "onlyOwner function"
    assert analyzer._check_access_pattern(code, "onlyOwner") == True
    assert analyzer._check_access_pattern(code, "delegatecall") == False

def test_generate_recommendations(analyzer):
    issues = [
        {"type": "unrestricted_access", "description": "Public access", "severity": "HIGH"},
        {"type": "centralized_control", "description": "Owner-only", "severity": "HIGH"}
    ]
    recommendations = analyzer._generate_recommendations(issues)
    assert len(recommendations) > 0
    assert isinstance(recommendations[0], str)

def test_multiple_access_issues(analyzer):
    # Simulate contract code with multiple access issues
    code = bytes.fromhex("7075626c69635f6f6e6c794f776e6572")  # "public_onlyOwner" in hex
    findings = analyzer._analyze_patterns(code)
    assert findings["risk_level"] == "HIGH"
    assert len(findings["access_issues"]) >= 2

def test_recommendations_unique(analyzer):
    issues = [
        {"type": "unrestricted_access", "description": "Public access", "severity": "HIGH"},
        {"type": "unrestricted_access", "description": "Public access", "severity": "HIGH"}
    ]
    recommendations = analyzer._generate_recommendations(issues)
    # Check that duplicate recommendations are removed
    assert len(recommendations) == len(set(recommendations))
