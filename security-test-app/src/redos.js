// Intentional ReDoS Vulnerability (CWE-1333) for DevSecOps testing
function validateInput(str) {
    // VULNERABLE: Catastrophic backtracking regex with nested quantifiers
    const regex = /(a+)+$/;
    return regex.test(str);
}

module.exports = { validateInput };
