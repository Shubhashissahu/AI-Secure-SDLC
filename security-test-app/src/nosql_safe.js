// Secure NoSQL Query (CWE-943 Remediation)
const sanitize = require('mongo-sanitize');

async function findAccountSafe(req, res, User) {
    // SECURE: Strip MongoDB operator characters and enforce string type
    const cleanUsername = String(sanitize(req.body.username || ''));
    const user = await User.findOne({ username: cleanUsername });
    res.json(user);
}

module.exports = { findAccountSafe };
