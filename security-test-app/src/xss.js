// Intentional Cross-Site Scripting (XSS) Vulnerability (CWE-79) for DevSecOps testing
const express = require('express');
const router = express.Router();

router.get('/profile', (req, res) => {
    // VULNERABLE: Direct reflection of query parameter in HTTP response
    res.send(req.query.username);
});

function renderUserProfile(userData) {
    const container = document.getElementById('profile-container');
    // VULNERABLE: Direct assignment to innerHTML without sanitization
    container.innerHTML = "<h2>Welcome " + userData.username + "</h2>";
}

module.exports = { router, renderUserProfile };
