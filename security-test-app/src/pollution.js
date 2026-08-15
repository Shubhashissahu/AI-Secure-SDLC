// Intentional Prototype Pollution Vulnerability (CWE-1321) for DevSecOps testing
function mergeObjects(target, source) {
    // VULNERABLE: Direct property assignment without __proto__ / constructor check
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}

module.exports = { mergeObjects };
