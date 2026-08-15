// Secure Redirection (CWE-601 Remediation)
const ALLOWED_HOSTS = ['example.com', 'app.example.com'];

function redirectUserSafe(req, res) {
    const target = req.query.target || '/';
    // SECURE: Allow relative paths or strictly validated domain targets
    if (target.startsWith('/') && !target.startsWith('//')) {
        return res.redirect(target);
    }
    try {
        const parsed = new URL(target);
        if (ALLOWED_HOSTS.includes(parsed.hostname)) {
            return res.redirect(parsed.toString());
        }
    } catch (e) {
        // invalid URL format
    }
    res.redirect('/home');
}

module.exports = { redirectUserSafe };
