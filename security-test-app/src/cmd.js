// Intentional Command Injection Vulnerability (CWE-78) for DevSecOps testing
const { exec } = require('child_process');

function pingHost(host) {
    // VULNERABLE: Direct string interpolation into shell exec call
    exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

module.exports = { pingHost };
