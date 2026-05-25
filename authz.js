'use strict'

const util = require('util')
const constants = require('haraka-constants')

const { escapeFilter } = require('./escape')
const { searchAll, poolGet } = require('./ldap-promise')

exports._verify_address = async function (uid, address, connection) {
  const pool = connection.server.notes.ldappool
  if (!pool) {
    connection.logerror(`Could not verify address ${address}  for UID ${uid}`)
    throw new Error('LDAP Pool not found!')
  }

  try {
    const client = await poolGet(pool)
    const config = this._get_search_conf(uid, address, connection)
    connection.logdebug(`Verifying address: ${util.inspect(config)}`)
    const entries = await searchAll(client, config.basedn, config)
    return entries.length > 0
  } catch (err) {
    connection.logerror(`Could not verify address ${address}  for UID ${uid}`)
    connection.logdebug(`${util.inspect(err)}`)
    throw err
  }
}

exports._get_search_conf = (user, address, connection) => {
  const pool = connection.server.notes.ldappool
  let filter = pool.config.authz.searchfilter || '(&(objectclass=*)(uid=%u)(mail=%a))'
  filter = filter.replace(/%u/g, escapeFilter(user)).replace(/%a/g, escapeFilter(address))
  return {
    basedn: pool.config.authz.basedn || pool.config.basedn,
    filter,
    scope: pool.config.authz.scope || pool.config.scope,
    attributes: ['dn'],
  }
}

exports.check_authz = async function (next, connection, params) {
  if (
    !connection.notes ||
    !connection.notes.auth_user ||
    !params ||
    !params[0] ||
    !params[0].address
  ) {
    connection.logerror(
      `${
        'Ignoring invalid call. Given params are ' + ' connection.notes:'
      }${util.inspect(connection.notes)} and params:${util.inspect(params)}`,
    )
    return next()
  }
  const uid = connection.notes.auth_user
  const address = params[0].address
  try {
    const verified = await this._verify_address(uid, address, connection)
    if (verified) return next()
    next(
      constants.deny,
      `User ${util.inspect(uid)} not allowed to send from address ${util.inspect(address)}.`,
    )
  } catch (err) {
    connection.logerror(`Could not use LDAP to match address to uid: ${err.message}`)
    next(constants.denysoft)
  }
}
