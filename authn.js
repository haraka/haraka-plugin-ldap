'use strict'

const util = require('util')

const { escapeFilter, escapeDN } = require('./escape')
const { bindAsync, searchAll, poolGet } = require('./ldap-promise')

exports._verify_user = async function (userdn, passwd, connection) {
  const pool = connection.server.notes.ldappool
  if (!pool) {
    connection.logerror(`Could not verify userdn and password: LDAP Pool not found`)
    return false
  }

  let client
  try {
    client = await new Promise((resolve, reject) => {
      pool._create_client((err, c) => (err ? reject(err) : resolve(c)))
    })
  } catch (err) {
    connection.logerror(`Could not verify userdn and password: ${util.inspect(err)}`)
    return false
  }

  try {
    await bindAsync(client, userdn, passwd)
    return true
  } catch (err) {
    connection.logdebug(`Login failed, could not bind ${util.inspect(userdn)}: ${util.inspect(err)}`)
    return false
  } finally {
    // fire-and-forget — awaiting unbind can hang when the bind already
    // closed the socket. ldapjs sets `unbound=true` synchronously in unbind().
    try {
      client.unbind()
    } catch (ignore) {}
  }
}

exports._get_search_conf = (user, connection) => {
  const pool = connection.server.notes.ldappool
  const filter = pool.config.authn.searchfilter || '(&(objectclass=*)(uid=%u))'
  return {
    basedn: pool.config.authn.basedn || pool.config.basedn,
    filter: filter.replace(/%u/g, escapeFilter(user)),
    scope: pool.config.authn.scope || pool.config.scope,
    attributes: ['dn'],
  }
}

exports._get_dn_for_uid = async function (uid, connection) {
  const pool = connection.server.notes.ldappool
  if (!pool) {
    connection.logerror(`Could not get DN for UID ${uid}`)
    throw new Error('LDAP Pool not found!')
  }

  try {
    const client = await poolGet(pool)
    const config = this._get_search_conf(uid, connection)
    connection.logdebug(`Getting DN for uid: ${util.inspect(config)}`)
    const entries = await searchAll(client, config.basedn, config)
    return entries.map((entry) => String(entry.dn))
  } catch (err) {
    connection.logerror(`Could not get DN for UID ${uid}`)
    connection.logdebug(`: ${util.inspect(err)}`)
    throw err
  }
}

exports.check_plain_passwd = async function (connection, user, passwd, cb) {
  if (Array.isArray(connection.server.notes.ldappool.config.authn.dn)) {
    return this.check_plain_passwd_dn(connection, user, passwd, cb)
  }

  connection.logdebug(`Looking up user ${util.inspect(user)} by search.`)
  let userdn
  try {
    userdn = await this._get_dn_for_uid(user, connection)
  } catch (err) {
    connection.logerror(`Could not use LDAP for password check: ${util.inspect(err)}`)
    return cb(false)
  }
  if (userdn.length !== 1) {
    connection.logdebug(
      `None or nonunique LDAP search result for user ${util.inspect(user)}, access denied`,
    )
    return cb(false)
  }
  cb(await this._verify_user(userdn[0], passwd, connection))
}

exports.check_plain_passwd_dn = async function (connection, user, passwd, cb) {
  connection.logdebug(`Looking up user ${util.inspect(user)} by DN.`)
  const dns = connection.server.notes.ldappool.config.authn.dn
  // Verify against each candidate DN in parallel; succeed on the first match.
  const results = await Promise.all(
    dns.map((dn) => this._verify_user(dn.replace(/%u/g, escapeDN(user)), passwd, connection)),
  )
  cb(results.some((ok) => ok))
}
