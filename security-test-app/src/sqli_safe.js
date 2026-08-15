// Secure Parameterized SQL Query (CWE-89 Remediation)
const express = require('express');
const router = express.Router();

router.get('/user-safe', async (req, res) => {
    const userId = req.query.id;
    // SECURE: Parameterized query prevents SQL injection
    const query = "SELECT * FROM users WHERE id = $1 AND status = $2";
    const user = await db.query(query, [userId, 'active']);
    res.json(user);
});

module.exports = router;
