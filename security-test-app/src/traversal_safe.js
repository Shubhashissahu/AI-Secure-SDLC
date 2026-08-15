// Secure File Access (CWE-22 Remediation)
const fs = require('fs');
const path = require('path');

function getDocumentSafe(req, res) {
    const filename = req.query.file;
    const baseDir = path.resolve('/var/www/uploads');
    // SECURE: Resolve canonical path and enforce base directory boundary
    const safePath = path.resolve(baseDir, path.basename(filename));
    if (!safePath.startsWith(baseDir)) {
        return res.status(403).send("Access denied");
    }
    const content = fs.readFileSync(safePath, 'utf8');
    res.send(content);
}

module.exports = { getDocumentSafe };
