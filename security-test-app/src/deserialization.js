// Intentional Insecure Deserialization Vulnerability (CWE-502) for DevSecOps testing
const nodeSerialize = require('node-serialize');

function processSession(sessionCookie) {
    // VULNERABLE: Unsafe object deserialization allows arbitrary code execution
    const sessionObj = nodeSerialize.unserialize(sessionCookie);
    return sessionObj;
}

module.exports = { processSession };
