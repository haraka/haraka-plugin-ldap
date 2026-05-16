'use strict'

const { describe, it, beforeEach } = require('node:test')
const assert = require('node:assert')

const fixtures = require('haraka-test-fixtures')
const Address = require('@haraka/email-address').Address
const btoa = require('btoa')
const constants = require('haraka-constants')
const pool = require('../pool')

let user, plugin, server, cfg, connection

function _set_up() {
  user = {
    uid: 'user1',
    dn: 'uid=user1,ou=users,dc=example,dc=com',
    password: 'ykaHsOzEZD',
    mail: 'user1@example.com',
  }
  plugin = new fixtures.plugin('ldap')
  server = { notes: {} }
  cfg = {
    main: {
      binddn: user.dn,
      bindpw: user.password,
      basedn: 'dc=example,dc=com',
    },
  }
  connection = fixtures.connection.createConnection()
  connection.server = {
    notes: {
      ldappool: new pool.LdapPool({
        main: {
          server: ['ldap://localhost:3389'],
          binddn: user.dn,
          bindpw: user.password,
          basedn: 'dc=example,dc=com',
        },
      }),
    },
  }
}

describe('handle_authn', () => {
  beforeEach(_set_up)

  it('ok with test user and PLAIN', (t, done) => {
    connection.server.notes.ldappool.config.authn = {}
    connection.notes.allowed_auth_methods = ['PLAIN', 'LOGIN']
    connection.notes.authenticating = true
    connection.notes.auth_method = 'PLAIN'
    plugin.auth_plain = function (result) {
      assert.ok(true)
      done()
    }
    const params = [btoa(`discard\0${user.uid}\0${user.password}`)]
    plugin.handle_authn(function () {}, connection, params)
  })

  it('ok with test user and LOGIN', (t, done) => {
    connection.server.notes.ldappool.config.authn = {}
    connection.notes.allowed_auth_methods = ['PLAIN', 'LOGIN']
    connection.notes.authenticating = true
    connection.notes.auth_method = 'LOGIN'
    plugin.auth_login = function () {
      assert.ok(true)
      done()
    }
    const params = [btoa(`discard\0${user.uid}\0${user.password}`)]
    plugin.handle_authn(function () {}, connection, params)
  })

  it('ignore without connection.notes.authenticating', (t, done) => {
    connection.server.notes.ldappool.config.authn = {}
    plugin.handle_authn(
      function () {
        assert.ok(true)
        done()
      },
      connection,
      [''],
    )
  })

  it('ignore with unknown AUTH', (t, done) => {
    connection.server.notes.ldappool.config.authn = {}
    connection.notes.allowed_auth_methods = ['PLAIN', 'LOGIN']
    connection.notes.authenticating = true
    connection.notes.auth_method = 'OPENSESAME'
    plugin.handle_authn(
      function () {
        assert.ok(true)
        done()
      },
      connection,
      [''],
    )
  })

  it('next if ldappool.config.authn is not set', (t, done) => {
    plugin.handle_authn(
      function () {
        assert.ok(true)
        done()
      },
      connection,
      [''],
    )
  })
})

describe('hook_capabilities', () => {
  beforeEach(_set_up)

  it('no tls no auth', (t, done) => {
    const cb = function (rc, msg) {
      assert.ok(connection.capabilities.length === 0)
      done()
    }
    connection.using_tls = false
    connection.capabilities = []
    plugin.hook_capabilities(cb, connection)
  })

  it('tls ante portas, ready for auth login', (t, done) => {
    const cb = function (rc, msg) {
      assert.ok(connection.notes.allowed_auth_methods.length === 2)
      assert.ok(connection.notes.allowed_auth_methods[0] === 'PLAIN')
      assert.ok(connection.notes.allowed_auth_methods[1] === 'LOGIN')
      assert.ok(connection.capabilities[0] === 'AUTH PLAIN LOGIN')
      done()
    }
    connection.using_tls = true
    connection.capabilities = []
    plugin.hook_capabilities(cb, connection)
  })
})

describe('check_plain_passwd', () => {
  beforeEach(_set_up)

  it('basic functionality: valid login ok', (t, done) => {
    plugin._init_ldappool(() => {
      connection.server.notes.ldappool.config.authn = {}
      plugin.check_plain_passwd(connection, user.uid, user.password, (result) => {
        assert.equal(true, result)
        done()
      })
    }, server)
  })

  it('basic functionality: invalid login fails', (t, done) => {
    plugin._init_ldappool(() => {
      connection.server.notes.ldappool.config.authn = {}
      plugin.check_plain_passwd(connection, user.uid, 'invalid', (result2) => {
        assert.equal(false, result2)
        done()
      })
    }, server)
  })
})

describe('aliases', () => {
  beforeEach(_set_up)

  it('basic functionality: resolve forwarding user', (t, done) => {
    connection.transaction = { rcpt_to: ['forwarder@example.com'] }
    connection.server.notes.ldappool.config.aliases = {}
    connection.server.notes.ldappool.config.aliases.searchfilter =
      '(&(objectclass=*)(mailLocalAddress=%a))'
    connection.server.notes.ldappool.config.aliases.attribute = 'mailRoutingAddress'
    plugin.aliases(
      function (result) {
        assert.equal(undefined, result)
        assert.equal('<user2@example.com>', connection.transaction.rcpt_to.toString())
        done()
      },
      connection,
      [
        {
          address: () => {
            return 'forwarder@example.com'
          },
        },
      ],
    )
  })

  it('next if ldappool.config.aliases is not set', (t, done) => {
    plugin.aliases(
      function () {
        assert.ok(true)
        done()
      },
      connection,
      [],
    )
  })
})

describe('check_rcpt', () => {
  beforeEach(_set_up)

  it('basic functionality: lookup recipient', (t, done) => {
    connection.server.notes.ldappool.config.rcpt_to = {
      searchfilter: '(&(objectclass=*)(mailLocalAddress=%a))',
    }
    plugin.check_rcpt(
      function (err) {
        assert.equal(constants.ok, err)
        done()
      },
      connection,
      [
        {
          address: () => {
            return 'user1@example.com'
          },
        },
      ],
    )
  })

  it('next if ldappool.config.rcpt_to is not set', (t, done) => {
    plugin.check_rcpt(
      function () {
        assert.ok(true)
        done()
      },
      connection,
      [],
    )
  })
})

describe('check_authz', () => {
  beforeEach(_set_up)

  it('basic functionality: matching address', (t, done) => {
    connection.server.notes.ldappool.config.authz = {
      searchfilter: '(&(objectclass=*)(uid=%u)(mailLocalAddress=%a))',
    }
    connection.notes = { auth_user: 'user1' }
    plugin.check_authz(
      function (err) {
        assert.ifError(err)
        done()
      },
      connection,
      [new Address('<user1@example.com>')],
    )
  })

  it('next if ldappool.config.authz is not set', (t, done) => {
    plugin.check_authz(
      function () {
        assert.ok(true)
        done()
      },
      connection,
      [],
    )
  })
})

describe('register', () => {
  beforeEach(_set_up)

  it('register sets master and child hooks to register pool', (t, done) => {
    assert.deepEqual(plugin.hooks, {})
    plugin.register()
    assert.deepEqual(plugin.hooks, {
      init_master: ['_init_ldappool'],
      init_child: ['_init_ldappool'],
      rcpt: ['aliases', 'check_rcpt'],
      mail: ['check_authz'],
      unrecognized_command: ['handle_authn'],
    })
    done()
  })
})

describe('_load_ldap_ini', () => {
  beforeEach(_set_up)

  it('check if values get loaded and set', (t, done) => {
    plugin._init_ldappool(() => {
      plugin._load_ldap_ini()
      assert.equal('uid=user1,ou=users,dc=example,dc=com', server.notes.ldappool.config.binddn)
      assert.equal('ykaHsOzEZD', server.notes.ldappool.config.bindpw)
      assert.equal('example.com', server.notes.ldappool.config.basedn)
      assert.equal('base', server.notes.ldappool.config.scope)
    }, server)
    done()
  })

  it('set _tmp_pool_config if pool is not available', (t, done) => {
    assert.equal(undefined, plugin._tmp_pool_config)
    plugin._load_ldap_ini()
    const conf = plugin._tmp_pool_config.main
    assert.equal('uid=user1,ou=users,dc=example,dc=com', conf.binddn)
    assert.equal('ykaHsOzEZD', conf.bindpw)
    assert.equal('example.com', conf.basedn)
    assert.equal('base', conf.scope)
    done()
  })
})

describe('_init_ldappool', () => {
  beforeEach(_set_up)

  it('check if this.server.notes.ldappool is set correctly', (t, done) => {
    plugin._init_ldappool(() => {
      assert.equal(true, server.notes.ldappool instanceof pool.LdapPool)
      assert.equal(true, plugin._pool instanceof pool.LdapPool)
      done()
    }, server)
  })

  it('test proper _tmp_pool_config handling', (t, done) => {
    plugin._load_ldap_ini()
    plugin._init_ldappool(() => {
      const conf = plugin._pool.config
      assert.equal('uid=user1,ou=users,dc=example,dc=com', conf.binddn)
      assert.equal('ykaHsOzEZD', conf.bindpw)
      assert.equal('example.com', conf.basedn)
      done()
    }, server)
  })
})

describe.skip('shutdown', () => {
  beforeEach(_set_up)

  it('make sure ldappool gets closed', (t, done) => {
    plugin._init_ldappool(() => {
      server.notes.ldappool.get((err, client) => {
        plugin.shutdown(() => {
          assert.equal(true, client.unbound)
          done()
        })
      })
    }, server)
  })
})
