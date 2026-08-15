// Secure Secrets Configuration (CWE-798 Remediation)
require('dotenv').config();

module.exports = {
    // SECURE: Secrets loaded from environment variables
    awsSecretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    databasePassword: process.env.DATABASE_PASSWORD
};
