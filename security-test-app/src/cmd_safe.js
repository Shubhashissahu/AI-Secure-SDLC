// Secure Command Execution (CWE-78 Remediation)
const { execFile } = require('child_process');

function pingHostSafe(host) {
    // SECURE: Input validation and execFile array argument prevents shell command injection
    if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
        throw new Error("Invalid host input");
    }
    execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
        console.log(stdout);
    });
}

module.exports = { pingHostSafe };
