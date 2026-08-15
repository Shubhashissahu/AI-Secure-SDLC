// Intentional Hardcoded Credentials Vulnerability (CWE-798) for DevSecOps testing
module.exports = {
    // VULNERABLE: Sensitive secrets committed in plain text to source code
    AWS_SECRET_ACCESS_KEY: "AKIAIOSFODNN7EXAMPLE",
    DATABASE_PASSWORD: "SuperSecretPassword123!"
};
