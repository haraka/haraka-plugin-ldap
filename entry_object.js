'use strict';

// ldapjs v3 removed `SearchEntry#object`. Reconstruct the v2-style
// POJO it used to return — `dn` plus each attribute, single-valued as
// a string and multi-valued as an array — so the rest of the plugin
// keeps working unchanged against ldapjs v3.
module.exports = function objectFromEntry(entry) {
    const pojo = entry.pojo;
    const obj = { dn: pojo.objectName };
    for (const { type, values } of pojo.attributes) {
        obj[type] = values.length === 1 ? values[0] : values;
    }
    return obj;
};
