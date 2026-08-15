const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    // ⚠️ VULN: Reflected XSS (CWE-79)
    res.send("<h1>Search results for: " + req.query.q + "</h1>");
});

module.exports = app;
