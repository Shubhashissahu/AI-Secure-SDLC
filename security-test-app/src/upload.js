// Intentional Insecure File Upload Vulnerability (CWE-434) for DevSecOps testing
const fs = require('fs');
const path = require('path');

function saveUpload(file) {
    // VULNERABLE: Direct use of original filename without extension or path sanitization
    const dest = path.join('/var/www/uploads', file.originalname);
    fs.writeFileSync(dest, file.buffer);
}

module.exports = { saveUpload };
