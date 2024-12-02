import pytest
from audit_tools.defi_attack_vectors import DeFiAttackVectorAnalyzer

@pytest.fixture
def analyzer():
    return DeFiAttackVectorAnalyzer()

def test_analyze_attack_vectors_invalid_address(analyzer):
    result = analyzer.analyze_attack_vectors("0xinvalid")
    assert "error" in result

def test_analyze_vectors_critical(analyzer):
    # Simulate contract code with critical attack vectors
    code = bytes.fromhex("666c6173685f6c6f616e")  # "flash_loan" in hex
    findings = analyzer._analyze_vectors(code)
    assert findings["risk_level"] == "CRITICAL"
    assert len(findings["attack_vectors"]) > 0

def test_analyze_vectors_high(analyzer):
    # Simulate contract code with high-risk attack vectors
    code = bytes.fromhex("66726f6e745f72756e")  # "front_run" in hex
    findings = analyzer._analyze_vectors(code)
    assert findings["risk_level"] == "HIGH"
    assert len(findings["attack_vectors"]) > 0

def test_analyze_vectors_low(analyzer):
    # Simulate contract code with no attack vectors
    code = bytes.fromhex("736166655f636f6465")  # "safe_code" in hex
    findings = analyzer._analyze_vectors(code)
    assert findings["risk_level"] == "LOW"
    assert len(findings["attack_vectors"]) == 0

def test_check_vector_pattern(analyzer):
    code = "flash_loan_function"
    assert analyzer._check_vector_pattern(code, "flash_loan") == True
    assert analyzer._check_vector_pattern(code, "sandwich") == False

def test_generate_mitigations(analyzer):
    vectors = [
        {
            "name": "flash_loan_attack",
            "description": "Flash loan attack vulnerability",
            "impact": "Price manipulation",
            "severity": "CRITICAL"
        },
        {
            "name": "reentrancy_attack",
            "description": "Reentrancy attack vulnerability",
            "impact": "Fund drainage",
            "severity": "CRITICAL"
        }
    ]
    mitigations = analyzer._generate_mitigations(vectors)
    assert len(mitigations) > 0
    assert isinstance(mitigations[0], str)

def test_multiple_attack_vectors(analyzer):
    # Simulate contract code with multiple attack vectors
    code = bytes.fromhex("666c6173685f6c6f616e5f7265656e7472616e6379")  # "flash_loan_reentrancy" in hex
    findings = analyzer._analyze_vectors(code)
    assert findings["risk_level"] == "CRITICAL"
    assert len(findings["attack_vectors"]) >= 2

def test_mitigations_unique(analyzer):
    vectors = [
        {
            "name": "flash_loan_attack",
            "description": "Flash loan attack vulnerability",
            "impact": "Price manipulation",
            "severity": "CRITICAL"
        },
        {
            "name": "flash_loan_attack",
            "description": "Flash loan attack vulnerability",
            "impact": "Price manipulation",
            "severity": "CRITICAL"
        }
    ]
    mitigations = analyzer._generate_mitigations(vectors)
    # Check that duplicate mitigations are removed
    assert len(mitigations) == len(set(mitigations))
