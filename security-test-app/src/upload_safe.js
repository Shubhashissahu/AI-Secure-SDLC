// Secure File Upload Handling (CWE-434 Remediation)
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ALLOWED_EXT = new Set(['.png', '.jpg', '.pdf']);

function saveUploadSafe(file) {
    // SECURE: Extension whitelist and generated random UUID filename
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXT.has(ext)) {
        throw new Error("Disallowed file type");
    }
    const safeName = crypto.randomUUID() + ext;
    const dest = path.join('/var/www/uploads', safeName);
    fs.writeFileSync(dest, file.buffer);
}

module.exports = { saveUploadSafe };
