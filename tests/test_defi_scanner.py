import pytest
from audit_tools.defi_scanner import DeFiScanner

@pytest.fixture
def scanner():
    return DeFiScanner()

def test_scan_contract_invalid_address(scanner):
    result = scanner.scan_contract("0xinvalid")
    assert "error" in result

def test_analyze_defi_risks_high(scanner):
    # Simulate contract code with high-risk patterns
    code = bytes.fromhex("666c6173685f6c6f616e")  # "flash_loan" in hex
    findings = scanner._analyze_defi_risks(code)
    assert findings["risk_level"] == "HIGH"
    assert len(findings["vulnerabilities"]) > 0

def test_analyze_defi_risks_medium(scanner):
    # Simulate contract code with medium-risk patterns
    code = bytes.fromhex("736c697070616765")  # "slippage" in hex
    findings = scanner._analyze_defi_risks(code)
    assert findings["risk_level"] == "MEDIUM"
    assert len(findings["vulnerabilities"]) > 0

def test_analyze_defi_risks_low(scanner):
    # Simulate contract code with no risk patterns
    code = bytes.fromhex("736166655f636f6465")  # "safe_code" in hex
    findings = scanner._analyze_defi_risks(code)
    assert findings["risk_level"] == "LOW"
    assert len(findings["vulnerabilities"]) == 0

def test_check_pattern(scanner):
    code = "flash_loan_function"
    assert scanner._check_pattern(code, "flash_loan") == True
    assert scanner._check_pattern(code, "reentrancy") == False

def test_generate_defi_recommendations(scanner):
    vulnerabilities = [
        {"type": "flash_loan", "description": "Flash loan vulnerability", "severity": "HIGH"},
        {"type": "price_oracle", "description": "Price oracle manipulation", "severity": "HIGH"}
    ]
    recommendations = scanner._generate_defi_recommendations(vulnerabilities)
    assert len(recommendations) > 0
    assert isinstance(recommendations[0], str)

def test_multiple_vulnerabilities(scanner):
    # Simulate contract code with multiple vulnerabilities
    code = bytes.fromhex("666c6173685f6c6f616e5f7072696365")  # "flash_loan_price" in hex
    findings = scanner._analyze_defi_risks(code)
    assert findings["risk_level"] == "HIGH"
    assert len(findings["vulnerabilities"]) >= 2

def test_recommendations_unique(scanner):
    vulnerabilities = [
        {"type": "flash_loan", "description": "Flash loan vulnerability", "severity": "HIGH"},
        {"type": "flash_loan", "description": "Flash loan vulnerability", "severity": "HIGH"}
    ]
    recommendations = scanner._generate_defi_recommendations(vulnerabilities)
    # Check that duplicate recommendations are removed
    assert len(recommendations) == len(set(recommendations))
