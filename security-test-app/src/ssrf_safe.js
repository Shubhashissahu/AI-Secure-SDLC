// Secure External URL Fetching (CWE-918 Remediation)
const axios = require('axios');
const { URL } = require('url');

const ALLOWED_HOSTS = ['api.github.com', 'hooks.slack.com'];

async function fetchWebhookSafe(req, res) {
    const targetUrl = req.query.url;
    try {
        const parsed = new URL(targetUrl);
        // SECURE: Domain whitelist and protocol enforcement
        if (!ALLOWED_HOSTS.includes(parsed.hostname) || parsed.protocol !== 'https:') {
            return res.status(400).send("Unauthorized target URL");
        }
        const response = await axios.get(parsed.toString(), { timeout: 3000 });
        res.json(response.data);
    } catch (e) {
        res.status(400).send("Invalid URL");
    }
}

module.exports = { fetchWebhookSafe };
