'use strict'

const { describe, it, beforeEach } = require('node:test')
const assert = require('node:assert')

const { makeConnection } = require('haraka-test-fixtures')
const ldappool = require('../lib/pool')

// test user data as defined in testdata.ldif
const users = [
  {
    uid: 'user1',
    dn: 'uid=user1,ou=users,dc=example,dc=com',
    password: 'ykaHsOzEZD',
    mail: 'user1@example.com',
  },
  {
    uid: 'user2',
    dn: 'uid=user2,ou=people,dc=example,dc=com',
    password: 'KQD9zs,LGv',
    mail: 'user2@example.com',
  },
  {
    uid: 'nonunique',
    dn: 'uid=nonunique,ou=users,dc=example,dc=com',
    password: 'CZVm3,BLlx',
    mail: 'nonunique1@example.com',
  },
  {
    uid: 'nonunique',
    dn: 'uid=nonunique,ou=people,dc=example,dc=com',
    password: 'LsBHDGorAh',
    mail: 'nonunique2@example.com',
  },
]

let plugin, connection

function _set_up(t, done) {
  plugin = require('../lib/authn')
  connection = makeConnection()
  connection.server = {
    notes: {
      ldappool: new ldappool.LdapPool({
        main: {
          server: ['ldap://localhost:3389'],
          binddn: users[0].dn,
          bindpw: users[0].password,
          basedn: 'dc=example,dc=com',
        },
      }),
    },
  }
  connection.server.notes.ldappool.config.authn = {}
  done()
}

describe('_verify_user', () => {
  beforeEach(_set_up)

  it('verifies test data', async () => {
    for (const user of users) {
      assert.equal(true, await plugin._verify_user(user.dn, user.password, connection))
    }
  })

  it('safety check: wrong password fails', async () => {
    assert.equal(false, await plugin._verify_user(users[0].dn, 'wrong', connection))
  })

  it('safety check: invalid dn fails', async () => {
    assert.equal(false, await plugin._verify_user('wrong', 'wrong', connection))
  })

  it('no pool', async () => {
    connection.server.notes.ldappool = undefined
    assert.equal(false, await plugin._verify_user(users[0].dn, users[0].password, connection))
  })
})

describe('_get_search_conf', () => {
  beforeEach(_set_up)

  it('get defaults', (t, done) => {
    const pool = connection.server.notes.ldappool
    const opts = plugin._get_search_conf('testUid', connection)
    assert.equal(opts.basedn, pool.config.basedn)
    assert.equal(opts.filter, '(&(objectclass=*)(uid=testUid))')
    assert.equal(opts.scope, pool.config.scope)
    assert.equal(opts.attributes.toString(), ['dn'].toString())
    done()
  })

  it('get userdef', (t, done) => {
    const pool = connection.server.notes.ldappool
    pool.config.authn.basedn = 'hop around as you like'
    pool.config.authn.searchfilter = '(&(objectclass=posixAccount)(uid=%u))'
    pool.config.authn.scope = 'one two three'
    const opts = plugin._get_search_conf('testUid', connection)
    assert.equal(opts.basedn, 'hop around as you like')
    assert.equal(opts.filter, '(&(objectclass=posixAccount)(uid=testUid))')
    assert.equal(opts.scope, 'one two three')
    assert.equal(opts.attributes.toString(), ['dn'].toString())
    done()
  })

  it('escapes %u substitutions per RFC 4515', (t, done) => {
    const opts = plugin._get_search_conf('*)(uid=*', connection)
    assert.equal(opts.filter, '(&(objectclass=*)(uid=\\2a\\29\\28uid=\\2a))')
    done()
  })
})

describe('get_dn_for_uid', () => {
  beforeEach(_set_up)

  it('user 1 dn2uid', async () => {
    const userdn = await plugin._get_dn_for_uid(users[0].uid, connection)
    assert.equal(userdn.toString(), users[0].dn)
  })

  it('user 2 dn2uid', async () => {
    const userdn = await plugin._get_dn_for_uid(users[1].uid, connection)
    assert.equal(userdn.toString(), users[1].dn)
  })

  it('nonunique dn2uid', async () => {
    const userdn = await plugin._get_dn_for_uid('nonunique', connection)
    assert.equal(2, userdn.length)
  })

  it('invalid uid', async () => {
    const userdn = await plugin._get_dn_for_uid('doesntexist', connection)
    assert.equal(0, userdn.length)
  })

  it('invalid search filter', async () => {
    const pool = connection.server.notes.ldappool
    pool.config.authn.searchfilter = '(&(objectclass=*)(uid=%u'
    await assert.rejects(plugin._get_dn_for_uid(users[0].uid, connection), {
      message: 'unbalanced parentheses',
    })
  })

  it('invalid basedn', async () => {
    connection.server.notes.ldappool.config.basedn = 'invalid'
    await assert.rejects(plugin._get_dn_for_uid(users[0].uid, connection))
  })

  it('no pool', async () => {
    connection.server.notes.ldappool = undefined
    await assert.rejects(plugin._get_dn_for_uid(users[0].uid, connection), {
      message: 'LDAP Pool not found!',
    })
  })
})

describe('check_plain_passwd', () => {
  beforeEach(_set_up)

  for (const user of users.slice(0, 2)) {
    it(`validates user ${user.uid}`, (t, done) => {
      plugin.check_plain_passwd(connection, user.uid, user.password, (result) => {
        assert.equal(true, result)
        done()
      })
    })
  }

  for (const user of users.slice(2)) {
    it(`rejects user ${user.uid}`, (t, done) => {
      plugin.check_plain_passwd(connection, user.uid, user.password, (result) => {
        assert.equal(false, result)
        done()
      })
    })
  }

  it(`rejects invalid user`, (t, done) => {
    plugin.check_plain_passwd(connection, 'invalid', 'invalid', (result) => {
      assert.equal(false, result)
      done()
    })
  })

  for (const user of users) {
    it(`dn validates user ${user.uid}`, (t, done) => {
      connection.server.notes.ldappool.config.authn.dn = [
        'uid=%u,ou=users,dc=example,dc=com',
        'uid=%u,ou=people,dc=example,dc=com',
      ]
      plugin.check_plain_passwd(connection, user.uid, user.password, (result) => {
        assert.strictEqual(true, result)
        done()
      })
    })
  }

  it(`dn rejects invalid user`, (t, done) => {
    connection.server.notes.ldappool.config.authn.dn = [
      'uid=%u,ou=users,dc=example,dc=com',
      'uid=%u,ou=people,dc=example,dc=com',
    ]
    plugin.check_plain_passwd(connection, 'invalid', 'invalid', (result) => {
      assert.equal(false, result)
      done()
    })
  })
})
