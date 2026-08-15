// Intentional XML External Entity (XXE) Injection Vulnerability (CWE-611) for DevSecOps testing
const libxmljs = require('libxmljs');

function parseXmlDoc(xmlString) {
    // VULNERABLE: External entity resolution enabled via noent: true
    const doc = libxmljs.parseXmlString(xmlString, { noent: true });
    return doc;
}

module.exports = { parseXmlDoc };
