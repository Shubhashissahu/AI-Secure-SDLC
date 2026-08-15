// Intentional SQL Injection Vulnerability (CWE-89) for DevSecOps testing
const express = require('express');
const router = express.Router();

router.get('/user', async (req, res) => {
    const userId = req.query.id;
    // VULNERABLE: Direct string concatenation into SQL query string
    const query = "SELECT * FROM users WHERE id = '" + userId + "' AND status = 'active'";
    const user = await db.query(query);
    res.json(user);
});

module.exports = router;
