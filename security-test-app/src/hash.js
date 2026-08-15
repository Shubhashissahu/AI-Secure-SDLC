// Intentional Weak Password Hashing Vulnerability (CWE-916) for DevSecOps testing
const crypto = require('crypto');

function hashPassword(password) {
    // VULNERABLE: MD5 hash is broken and vulnerable to collision and dictionary attacks
    return crypto.createHash("md5").update(password).digest('hex');
}

module.exports = { hashPassword };
