// Secure XML Parsing (CWE-611 Remediation)
const libxmljs = require('libxmljs');

function parseXmlDocSafe(xmlString) {
    // SECURE: External entity resolution and DTD loading disabled
    const doc = libxmljs.parseXmlString(xmlString, { noent: false, nonet: true, dtdload: false });
    return doc;
}

module.exports = { parseXmlDocSafe };
