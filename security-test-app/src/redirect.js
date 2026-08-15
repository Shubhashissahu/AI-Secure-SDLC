// Intentional Open Redirect Vulnerability (CWE-601) for DevSecOps testing
function redirectUser(req, res) {
    // VULNERABLE: Directly redirecting to user-controlled URL
    res.redirect(req.query.target);
}

module.exports = { redirectUser };
