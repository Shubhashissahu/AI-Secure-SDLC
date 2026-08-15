// Intentional LDAP Injection Vulnerability (CWE-90) for DevSecOps testing
function searchLdapUser(client, username) {
    // VULNERABLE: Direct concatenation of user input into LDAP filter
    client.search('dc=example,dc=com', { filter: "(&(objectClass=user)(uid=" + username + "))" }, (err, res) => {
        console.log("Search completed");
    });
}

module.exports = { searchLdapUser };
