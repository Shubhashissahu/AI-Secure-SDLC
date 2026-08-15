// Intentional Weak Cryptography Vulnerability (CWE-327) for DevSecOps testing
const crypto = require('crypto');

function encryptData(key, text) {
    // VULNERABLE: Deprecated DES cipher used
    const cipher = crypto.createCipheriv("des", key, Buffer.alloc(8));
    return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

module.exports = { encryptData };
