// Secure Encryption (CWE-327 Remediation)
const crypto = require('crypto');

function encryptDataSafe(key, text) {
    // SECURE: AES-256-GCM authenticated encryption with random IV
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { iv: iv.toString('hex'), ciphertext: encrypted.toString('hex'), tag: tag.toString('hex') };
}

module.exports = { encryptDataSafe };
