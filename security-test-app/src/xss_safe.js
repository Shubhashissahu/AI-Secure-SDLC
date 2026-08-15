// Secure HTML Rendering (CWE-79 Remediation)
const DOMPurify = require('dompurify');

function renderUserProfileSafe(userData) {
    const container = document.getElementById('profile-container');
    // SECURE: User data sanitized with DOMPurify
    const safeUsername = DOMPurify.sanitize(userData.username);
    const safeBio = DOMPurify.sanitize(userData.bio);
    container.textContent = `Welcome ${safeUsername} - ${safeBio}`;
}

module.exports = { renderUserProfileSafe };
