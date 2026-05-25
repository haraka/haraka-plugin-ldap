'use strict'

const { describe, it, beforeEach } = require('node:test')
const assert = require('node:assert')
const util = require('util')

const fixtures = require('haraka-test-fixtures')
const constants = require('haraka-constants')
const ldappool = require('../pool')

let user, group, plugin, connection

function _set_up(t, done) {
  user = {
    uid: 'user1',
    dn: 'uid=user1,ou=users,dc=example,dc=com',
    password: 'ykaHsOzEZD',
    mail: 'user1@example.com',
  }
  group = {
    dn: 'cn=postmaster,dc=example,dc=com',
    mail: 'postmaster@example.com',
    member: [
      'uid=user1,ou=users,dc=example,dc=com',
      'uid=user2,ou=people,dc=example,dc=com',
      'uid=nonunique,ou=users,dc=example,dc=com',
    ],
  }
  plugin = require('../aliases')
  connection = fixtures.connection.createConnection()
  connection.transaction = {}
  connection.server = {
    notes: {
      ldappool: new ldappool.LdapPool({
        main: {
          server: ['ldap://localhost:3389'],
          binddn: user.dn,
          bindpw: user.password,
          basedn: 'dc=example,dc=com',
        },
      }),
    },
  }
  connection.server.notes.ldappool.config.aliases = {
    subattribute: 'mailLocalAddress',
    attribute: 'member',
    searchfilter: '(&(objectclass=groupOfNames)(mailLocalAddress=%a))',
  }
  done()
}

describe('_get_alias', () => {
  beforeEach(_set_up)

  it('ok with test group', async () => {
    connection.server.notes.ldappool.config.aliases.attribute_is_dn = true
    const result = await plugin._get_alias(group.mail, connection)
    assert.deepStrictEqual(
      ['nonunique1@example.com', 'user1@example.com', 'user2@example.com'],
      result.sort(),
    )
  })

  it('ok with forwarding user', async () => {
    connection.server.notes.ldappool.config.aliases.searchfilter =
      '(&(objectclass=*)(mailLocalAddress=%a))'
    connection.server.notes.ldappool.config.aliases.attribute = 'mailRoutingAddress'
    const result = await plugin._get_alias('forwarder@example.com', connection)
    assert.equal('user2@example.com', result[0])
  })

  it('ok with resolve-by-dn', async () => {
    connection.server.notes.ldappool.config.aliases.attribute_is_dn = true
    const expected = ['user1@example.com', 'user2@example.com', 'nonunique1@example.com']
    expected.sort()
    const result = await plugin._get_alias('postmaster@example.com', connection)
    result.sort()
    assert.equal(util.inspect(expected), util.inspect(result))
  })

  it('empty result with invalid mail', async () => {
    const result = await plugin._get_alias('invalid@email', connection)
    assert.deepStrictEqual([], result)
  })
})

describe('_get_search_conf_alias', () => {
  beforeEach(_set_up)

  it('get defaults', (t, done) => {
    const pool = connection.server.notes.ldappool
    pool.config.aliases.searchfilter = undefined
    pool.config.aliases.attribute = undefined
    const opts = plugin._get_search_conf_alias('testMail', connection)
    assert.equal(opts.basedn, pool.config.basedn)
    assert.equal(opts.filter, '(&(objectclass=*)(mail=testMail)(mailForwardAddress=*))')
    assert.equal(opts.scope, pool.config.scope)
    assert.equal(opts.attributes.toString(), ['mailForwardingAddress'].toString())
    done()
  })

  it('get userdef', (t, done) => {
    const pool = connection.server.notes.ldappool
    pool.config.aliases.basedn = 'hop around as you like'
    pool.config.aliases.searchfilter = '(&(objectclass=posixAccount)(mail=%a))'
    pool.config.aliases.scope = 'one two three'
    const opts = plugin._get_search_conf_alias('testMail', connection)
    assert.equal(opts.basedn, 'hop around as you like')
    assert.equal(opts.filter, '(&(objectclass=posixAccount)(mail=testMail))')
    assert.equal(opts.scope, 'one two three')
    assert.equal(opts.attributes.toString(), ['member'].toString())
    done()
  })

  it('escapes %a substitutions per RFC 4515', (t, done) => {
    const pool = connection.server.notes.ldappool
    pool.config.aliases.searchfilter = undefined
    const opts = plugin._get_search_conf_alias('*)(mail=*', connection)
    assert.equal(
      opts.filter,
      '(&(objectclass=*)(mail=\\2a\\29\\28mail=\\2a)(mailForwardAddress=*))',
    )
    done()
  })
})

describe('_resolve_dn_to_alias', () => {
  beforeEach(_set_up)

  it('ok one', async () => {
    const result = await plugin._resolve_dn_to_alias([user.dn], connection)
    assert.equal(user.mail, result)
  })

  it('ok multiple', async () => {
    const result = await plugin._resolve_dn_to_alias(group.member, connection)
    result.sort()
    assert.equal('nonunique1@example.com', result[0])
    assert.equal('user1@example.com', result[1])
    assert.equal('user2@example.com', result[2])
  })

  it('empty array when unknown dn', async () => {
    const result = await plugin._resolve_dn_to_alias(['uid=unknown,dc=wherever,dc=com'], connection)
    assert.equal(0, result.length)
  })
})

describe('aliases', () => {
  beforeEach(_set_up)

  it('ignore if invalid call / no rcpt', (t, done) => {
    function noParams(result) {
      assert.equal(undefined, result)
      plugin.aliases(noRcpt, connection, [])
    }
    function noRcpt(result) {
      assert.equal(undefined, result)
      plugin.aliases(noRcptAddress, connection, [{}])
    }
    function noRcptAddress(result) {
      assert.equal(undefined, result)
      done()
    }
    plugin.aliases(noParams, connection)
  })

  it('DENYSOFT if LDAP not usable', (t, done) => {
    connection.server.notes.ldappool.config.aliases.searchfilter =
      '(&(objectclass=posixAccount)(mail=%a'
    plugin.aliases(
      function (result) {
        assert.equal(constants.denysoft, result)
        done()
      },
      connection,
      [{ address: user.mail }],
    )
  })
  it('next if no results', (t, done) => {
    function next(result) {
      assert.equal(undefined, result)
      done()
    }
    plugin.aliases(next, connection, [{ address: 'unknown@mail' }])
  })
  it('resolve group members', (t, done) => {
    connection.transaction = { rcpt_to: [group.mail] }
    connection.server.notes.ldappool.config.aliases.attribute_is_dn = true
    const expected = ['<user1@example.com>', '<user2@example.com>', '<nonunique1@example.com>']
    expected.sort()
    function next(result) {
      assert.equal(undefined, result)
      connection.transaction.rcpt_to.sort()
      assert.equal(expected.toString(), connection.transaction.rcpt_to.toString())
      done()
    }
    plugin.aliases(next, connection, [{ address: group.mail }])
  })
  it('do not change non-aliased user', (t, done) => {
    connection.transaction = { rcpt_to: ['still the same'] }
    function next(result) {
      assert.equal(undefined, result)
      assert.equal('still the same', connection.transaction.rcpt_to.toString())
      done()
    }
    plugin.aliases(next, connection, [{ address: user.mail }])
  })
  it('resolve forwarding user', (t, done) => {
    connection.transaction = { rcpt_to: ['forwarder@example.com'] }
    connection.server.notes.ldappool.config.aliases.searchfilter =
      '(&(objectclass=*)(mailLocalAddress=%a))'
    connection.server.notes.ldappool.config.aliases.attribute = 'mailRoutingAddress'
    function next(result) {
      assert.equal(undefined, result)
      assert.equal('<user2@example.com>', connection.transaction.rcpt_to.toString())
      done()
    }
    plugin.aliases(next, connection, [{ address: 'forwarder@example.com' }])
  })
})
