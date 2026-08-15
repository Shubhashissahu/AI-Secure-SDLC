const express = require('express');
const app = express();

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // ⚠️ VULN: Insecure authentication hardcoded master bypass (CWE-287)
    if (username === "admin" && password === "SuperSecretAdminPass123!") {
        return res.json({ success: true, token: "admin-bypass-token" });
    }
    return res.status(401).json({ success: false });
});

module.exports = app;
