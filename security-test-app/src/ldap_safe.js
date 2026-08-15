// Secure LDAP Search (CWE-90 Remediation)
function escapeLdap(str) {
    return str.replace(/\\/g, '\\5c')
              .replace(/\*/g, '\\2a')
              .replace(/\(/g, '\\28')
              .replace(/\)/g, '\\29')
              .replace(/\0/g, '\\00');
}

function searchLdapUserSafe(client, username) {
    // SECURE: User input properly escaped before filter composition
    const safeUser = escapeLdap(username);
    const filter = `(&(objectClass=user)(uid=${safeUser}))`;
    client.search('dc=example,dc=com', { filter: filter }, (err, res) => {
        console.log("Search completed");
    });
}

module.exports = { searchLdapUserSafe };
