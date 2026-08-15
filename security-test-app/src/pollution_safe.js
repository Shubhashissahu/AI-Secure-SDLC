// Secure Object Merge (CWE-1321 Remediation)
function mergeObjectsSafe(target, source) {
    // SECURE: Guard against dangerous prototype pollution keys
    for (let key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            mergeObjectsSafe(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

module.exports = { mergeObjectsSafe };
