'use strict'

const { describe, it, beforeEach } = require('node:test')
const assert = require('node:assert')

const fixtures = require('haraka-test-fixtures')
const constants = require('haraka-constants')
const ldappool = require('../pool')

let user, plugin, connection

function _set_up(t, done) {
  user = {
    uid: 'user1',
    dn: 'uid=user1,ou=users,dc=example,dc=com',
    password: 'ykaHsOzEZD',
    mail: 'user1@example.com',
  }
  plugin = require('../rcpt_to')
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
  connection.server.notes.ldappool.config.rcpt_to = {
    searchfilter: '(&(objectclass=*)(mailLocalAddress=%a))',
  }
  done()
}

describe('_verify_existence', () => {
  beforeEach(_set_up)

  it('default user', async () => {
    assert.equal(true, await plugin._verify_existence(user.mail, connection))
  })

  it('invalid address', async () => {
    assert.equal(false, await plugin._verify_existence('unknown', connection))
  })

  it('invalid search filter', async () => {
    connection.server.notes.ldappool.config.rcpt_to.searchfilter = '(&(objectclass=*)(|(mail=%a'
    await assert.rejects(plugin._verify_existence(user.mail, connection), {
      message: 'unbalanced parentheses',
    })
  })

  it('no pool', async () => {
    connection.server.notes.ldappool = undefined
    await assert.rejects(plugin._verify_existence(user.mail, connection), {
      message: 'LDAP Pool not found!',
    })
  })
})

describe('_get_search_conf', () => {
  beforeEach(_set_up)

  it('get defaults', (t, done) => {
    const opts = plugin._get_search_conf('testMail', connection)
    const pool = connection.server.notes.ldappool
    assert.equal(opts.basedn, pool.config.basedn)
    assert.equal(opts.filter, '(&(objectclass=*)(mailLocalAddress=testMail))')
    assert.equal(opts.scope, pool.config.scope)
    assert.equal(opts.attributes.toString(), ['dn'].toString())
    done()
  })

  it('get userdef', (t, done) => {
    connection.server.notes.ldappool.config.rcpt_to.basedn = 'hop around as you like'
    connection.server.notes.ldappool.config.rcpt_to.searchfilter =
      '(&(objectclass=posixAccount)(mail=%a))'
    connection.server.notes.ldappool.config.rcpt_to.scope = 'one two three'
    const opts = plugin._get_search_conf('testMail', connection)
    assert.equal(opts.basedn, 'hop around as you like')
    assert.equal(opts.filter, '(&(objectclass=posixAccount)(mail=testMail))')
    assert.equal(opts.scope, 'one two three')
    assert.equal(opts.attributes.toString(), ['dn'].toString())
    done()
  })

  it('escapes %a substitutions per RFC 4515', (t, done) => {
    const opts = plugin._get_search_conf('*)(uid=*', connection)
    assert.equal(opts.filter, '(&(objectclass=*)(mailLocalAddress=\\2a\\29\\28uid=\\2a))')
    done()
  })
})

describe('check_rcpt', () => {
  beforeEach(_set_up)

  it('ok', (t, done) => {
    plugin.check_rcpt(
      function (err) {
        assert.equal(constants.ok, err)
        done()
      },
      connection,
      [{ address: 'user1@example.com' }],
    )
  })

  it('denysoft on error', (t, done) => {
    connection.server.notes.ldappool.config.rcpt_to.searchfilter = '(&(objectclass=*)(|(mail=%a'
    plugin.check_rcpt(
      function (err) {
        assert.equal(constants.denysoft, err)
        done()
      },
      connection,
      [{ address: 'user1@example.com' }],
    )
  })

  it('ignore if missing params[0]', (t, done) => {
    plugin.check_rcpt(
      function (err) {
        assert.equal(undefined, err)
        done()
      },
      connection,
      [],
    )
  })

  it('deny on invalid address', (t, done) => {
    plugin.check_rcpt(
      function (err) {
        assert.equal(constants.deny, err)
        done()
      },
      connection,
      [{ address: 'unknown@address' }],
    )
  })
})
