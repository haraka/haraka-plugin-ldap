'use strict'

// Thin promise wrappers over the callback-only ldapjs v3 client API.
// Each helper settles exactly once, so callers don't need their own
// once-guards.

const { promisify } = require('node:util')

exports.bindAsync = (client, dn, pw) => promisify(client.bind.bind(client))(dn, pw)

exports.unbindAsync = (client) => promisify(client.unbind.bind(client))()

// Run a search and resolve with the collected entries.
// ldapjs's `search()` invokes its callback with an EventEmitter rather than
// the results, so promisify can't handle it directly. We attach the three
// terminal listeners (searchEntry / error / end) and settle on the first
// one that fires a terminal event.
exports.searchAll = (client, base, opts) =>
  new Promise((resolve, reject) => {
    client.search(base, opts, (search_error, res) => {
      if (search_error) return reject(search_error)
      const entries = []
      let settled = false
      const settle = (fn, value) => {
        if (settled) return
        settled = true
        fn(value)
      }
      res.on('searchEntry', (entry) => entries.push(entry))
      res.on('error', (err) => settle(reject, err))
      res.on('end', () => settle(resolve, entries))
    })
  })

exports.poolGet = (pool) =>
  new Promise((resolve, reject) => {
    pool.get((err, client) => (err ? reject(err) : resolve(client)))
  })
