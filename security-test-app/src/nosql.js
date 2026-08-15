// Intentional NoSQL Injection Vulnerability (CWE-943) for DevSecOps testing
async function findAccount(req, res, User) {
    // VULNERABLE: Direct passing of request body object allows operator injection ($gt, $ne)
    const user = await User.findOne({ username: req.body });
    res.json(user);
}

module.exports = { findAccount };
