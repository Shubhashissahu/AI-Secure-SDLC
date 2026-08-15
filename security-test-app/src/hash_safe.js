// Secure Password Hashing (CWE-916 Remediation)
const bcrypt = require('bcrypt');

async function hashPasswordSafe(password) {
    // SECURE: Use strong salted bcrypt hashing with work factor 12
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}

module.exports = { hashPasswordSafe };
