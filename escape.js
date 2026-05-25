'use strict'

// RFC 4515 §3 — escape assertion values used inside an LDAP search filter.
// Five characters must become \HH (hex of the UTF-8 byte):
//   NUL (\00), * (\2a), ( (\28), ) (\29), \ (\5c)
// Non-ASCII bytes are valid in the filter and need no escaping for the
// directory; we leave them alone.
exports.escapeFilter = (value) => {
  if (value === null || value === undefined) return ''
  return String(value).replace(/[\0()*\\]/g, (ch) => {
    return '\\' + ch.charCodeAt(0).toString(16).padStart(2, '0')
  })
}

// RFC 4514 §2.4 — escape an attribute value embedded in a DN.
//   - Always escape: NUL, ", +, ,, ;, <, >, \
//   - Escape `#` only when it is the first character
//   - Escape ` ` (space) only at the start or end of the value
// `=` is permitted inside a value and need not be escaped, but we escape it
// defensively to remove any ambiguity if an attacker tries to inject an
// extra attribute-value pair.
exports.escapeDN = (value) => {
  if (value === null || value === undefined) return ''
  const s = String(value)
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]
    const isFirst = i === 0
    const isLast = i === s.length - 1
    if (ch === '\0') {
      out += '\\00'
    } else if ('"+,;<>\\='.includes(ch)) {
      out += '\\' + ch
    } else if (ch === '#' && isFirst) {
      out += '\\#'
    } else if (ch === ' ' && (isFirst || isLast)) {
      out += '\\ '
    } else {
      out += ch
    }
  }
  return out
}
