'use strict'

const util = require('util')
const constants = require('haraka-constants')

const { escapeFilter } = require('./escape')
const { searchAll, poolGet } = require('./ldap-promise')

exports._verify_existence = async function (address, connection) {
  const pool = connection.server.notes.ldappool
  if (!pool) {
    connection.logerror(`Could not verify address ${address}`)
    throw new Error('LDAP Pool not found!')
  }

  try {
    const client = await poolGet(pool)
    const config = this._get_search_conf(address, connection)
    connection.logdebug(`Verifying existence: ${util.inspect(config)}`)
    const entries = await searchAll(client, config.basedn, config)
    return entries.length > 0
  } catch (err) {
    connection.logerror(`Could not verify address ${address}`)
    connection.logdebug(`${util.inspect(err)}`)
    throw err
  }
}

exports._get_search_conf = (address, connection) => {
  const pool = connection.server.notes.ldappool
  let filter = pool.config.rcpt_to.searchfilter || '(&(objectclass=*)(mail=%a))'
  filter = filter.replace(/%a/g, escapeFilter(address))
  return {
    basedn: pool.config.rcpt_to.basedn || pool.config.basedn,
    filter,
    scope: pool.config.rcpt_to.scope || pool.config.scope,
    attributes: ['dn'],
  }
}

exports.check_rcpt = async function (next, connection, params) {
  if (!params || !params[0] || !params[0].address) {
    connection.logerror(
      `Ignoring invalid call. Given connection.transaction: ${util.inspect(connection.transaction)}`,
    )
    return next()
  }
  try {
    const exists = await this._verify_existence(params[0].address, connection)
    next(exists ? constants.ok : constants.deny)
  } catch (err) {
    connection.logerror(`Could not use LDAP for address check: ${err.message}`)
    next(constants.denysoft)
  }
}
