// Intentional Server-Side Request Forgery (SSRF) Vulnerability (CWE-918) for DevSecOps testing
const axios = require('axios');

async function fetchWebhook(req, res) {
    const targetUrl = req.query.url;
    // VULNERABLE: Direct request to user-supplied URL without validation
    const response = await axios.get(targetUrl);
    res.json(response.data);
}

module.exports = { fetchWebhook };
