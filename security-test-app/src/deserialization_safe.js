// Secure JSON Parsing (CWE-502 Remediation)
function processSessionSafe(sessionCookie) {
    // SECURE: Standard JSON parsing without executable object functions
    try {
        const sessionObj = JSON.parse(sessionCookie);
        return sessionObj;
    } catch (e) {
        throw new Error("Invalid session format");
    }
}

module.exports = { processSessionSafe };
