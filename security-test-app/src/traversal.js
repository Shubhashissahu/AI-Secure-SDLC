// Intentional Path Traversal Vulnerability (CWE-22) for DevSecOps testing
const fs = require('fs');
const path = require('path');

function getDocument(req, res) {
    const filename = req.query.file;
    // VULNERABLE: Direct path concatenation without boundary validation
    const content = fs.readFileSync(path.join('/var/www/uploads', filename), 'utf8');
    res.send(content);
}

module.exports = { getDocument };
