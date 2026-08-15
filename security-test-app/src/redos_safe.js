// Secure Regex Validation (CWE-1333 Remediation)
function validateInputSafe(str) {
    // SECURE: Linear-time regex without nested quantifiers and bounded string length
    if (str.length > 256) return false;
    const regex = /^a+$/;
    return regex.test(str);
}

module.exports = { validateInputSafe };
