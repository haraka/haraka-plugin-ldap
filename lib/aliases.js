'use strict'

const util = require('util')
const { Address } = require('@haraka/email-address')
const constants = require('haraka-constants')

const { escapeFilter } = require('./escape')
const { searchAll, poolGet } = require('./ldap-promise')

// Pull an attribute's values off an ldapjs v3 search entry. `.values`
// is always an array (empty if the attribute is absent).
const attrValues = (entry, name) => entry.attributes.find((a) => a.type === name)?.values ?? []

exports._get_alias = async function (address, connection) {
  const pool = connection.server.notes.ldappool
  if (!pool) {
    connection.logerror(`Could not resolve ${address} as alias`)
    throw new Error('LDAP Pool not found!')
  }

  let alias
  try {
    const client = await poolGet(pool)
    const config = this._get_search_conf_alias(address, connection)
    connection.logdebug(`Checking address for alias: ${util.inspect(config)}`)
    const entries = await searchAll(client, config.basedn, config)
    alias = entries.flatMap((entry) => attrValues(entry, config.attributes[0]))
  } catch (err) {
    connection.logerror(`Could not resolve ${address} as alias`)
    connection.logdebug(`${util.inspect(err)}`)
    throw err
  }

  if (pool.config.aliases.attribute_is_dn) {
    return this._resolve_dn_to_alias(alias, connection)
  }
  return alias
}

exports._get_search_conf_alias = (address, connection) => {
  const pool = connection.server.notes.ldappool
  let filter =
    pool.config.aliases.searchfilter || '(&(objectclass=*)(mail=%a)(mailForwardAddress=*))'
  filter = filter.replace(/%a/g, escapeFilter(address))
  return {
    basedn: pool.config.aliases.basedn || pool.config.basedn,
    filter,
    scope: pool.config.aliases.scope || pool.config.scope,
    attributes: [pool.config.aliases.attribute || 'mailForwardingAddress'],
  }
}

exports._resolve_dn_to_alias = async function (dns, connection) {
  const pool = connection.server.notes.ldappool
  if (!pool) {
    connection.logerror(`Could not get address for DN ${util.inspect(dns)}`)
    throw new Error('LDAP Pool not found!')
  }
  const config = {
    scope: 'base',
    attributes: [pool.config.aliases.subattribute || 'mailLocalAddress'],
  }

  let client
  try {
    client = await poolGet(pool)
  } catch (err) {
    connection.logerror(`Could not get address for DN ${util.inspect(dns)}: ${util.inspect(err)}`)
    throw err
  }
  connection.logdebug(`Resolving DN ${util.inspect(dns)} to alias: ${util.inspect(config)}`)

  // Resolve every DN in parallel; a per-DN failure produces [] for that DN
  // rather than failing the whole batch, matching the pre-async behavior.
  const results = await Promise.all(
    dns.map(async (d) => {
      try {
        const entries = await searchAll(client, d, config)
        return entries.map((entry) => attrValues(entry, config.attributes[0])[0])
      } catch (e) {
        connection.logwarn(`Could not retrieve DN ${util.inspect(d)}`)
        connection.logdebug(`${util.inspect(e)}`)
        return []
      }
    }),
  )
  return results.flat()
}

exports.aliases = async function (next, connection, params) {
  if (!params || !params[0] || !params[0].address) {
    connection.logerror(`Ignoring invalid call. Given params: ${util.inspect(params)}`)
    return next()
  }
  const rcpt = params[0].address
  let result
  try {
    result = await this._get_alias(rcpt, connection)
  } catch (err) {
    connection.logerror(`Could not use LDAP to resolve aliases: ${err.message}`)
    return next(constants.denysoft)
  }
  if (result.length === 0) {
    connection.logdebug(`No aliases results found for rcpt: ${util.inspect(rcpt)}`)
    return next()
  }
  connection.logdebug(this, `Aliasing ${util.inspect(rcpt)} to ${util.inspect(result)}`)
  connection.transaction.rcpt_to.pop()
  for (const element of result) {
    connection.transaction.rcpt_to.push(new Address(`<${element}>`))
  }
  next()
}
