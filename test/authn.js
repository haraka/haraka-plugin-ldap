'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert');

const fixtures = require('haraka-test-fixtures');
const ldappool = require('../pool');

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
];

let plugin, connection;

function _set_up(t, done) {
    plugin = require('../authn');
    connection = fixtures.connection.createConnection();
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
    };
    connection.server.notes.ldappool.config.authn = {};
    done();
}

describe('_verify_user', () => {
    beforeEach(_set_up);

    it('verifies test data', (t, done) => {
        let counter = 0;
        for (const user of users) {
            plugin._verify_user(
                user.dn,
                user.password,
                (result) => {
                    assert.equal(true, result);
                    counter++;
                    if (counter === users.length) done();
                },
                connection,
            );
        }
    });

    it('safety check: wrong password fails', (t, done) => {
        plugin._verify_user(
            users[0].dn,
            'wrong',
            function (ok) {
                assert.equal(false, ok);
                done();
            },
            connection,
        );
    });

    it('safety check: invalid dn fails', (t, done) => {
        plugin._verify_user(
            'wrong',
            'wrong',
            function (ok) {
                assert.equal(false, ok);
                done();
            },
            connection,
        );
    });

    it('no pool', (t, done) => {
        connection.server.notes.ldappool = undefined;
        const user = users[0];
        plugin._verify_user(
            user.dn,
            user.password,
            function (result) {
                assert.equal(false, result);
                done();
            },
            connection,
        );
    });
});

describe('_get_search_conf', () => {
    beforeEach(_set_up);

    it('get defaults', (t, done) => {
        const pool = connection.server.notes.ldappool;
        const opts = plugin._get_search_conf('testUid', connection);
        assert.equal(opts.basedn, pool.config.basedn);
        assert.equal(opts.filter, '(&(objectclass=*)(uid=testUid))');
        assert.equal(opts.scope, pool.config.scope);
        assert.equal(opts.attributes.toString(), ['dn'].toString());
        done();
    });

    it('get userdef', (t, done) => {
        const pool = connection.server.notes.ldappool;
        pool.config.authn.basedn = 'hop around as you like';
        pool.config.authn.searchfilter = '(&(objectclass=posixAccount)(uid=%u))';
        pool.config.authn.scope = 'one two three';
        const opts = plugin._get_search_conf('testUid', connection);
        assert.equal(opts.basedn, 'hop around as you like');
        assert.equal(opts.filter, '(&(objectclass=posixAccount)(uid=testUid))');
        assert.equal(opts.scope, 'one two three');
        assert.equal(opts.attributes.toString(), ['dn'].toString());
        done();
    });
});

describe('get_dn_for_uid', () => {
    beforeEach(_set_up);

    it('user 1 dn2uid', (t, done) => {
        plugin._get_dn_for_uid(
            users[0].uid,
            function (err, userdn) {
                assert.equal(null, err);
                assert.equal(userdn.toString(), users[0].dn);
                done();
            },
            connection,
        );
    });

    it('user 2 dn2uid', (t, done) => {
        plugin._get_dn_for_uid(
            users[1].uid,
            function (err, userdn) {
                assert.equal(null, err);
                assert.equal(userdn.toString(), users[1].dn);
                done();
            },
            connection,
        );
    });

    it('nonunique dn2uid', (t, done) => {
        plugin._get_dn_for_uid(
            'nonunique',
            function (err, userdn) {
                assert.equal(null, err);
                assert.equal(2, userdn.length);
                done();
            },
            connection,
        );
    });

    it('invalid uid', (t, done) => {
        plugin._get_dn_for_uid(
            'doesntexist',
            function (err, userdn) {
                assert.equal(null, err);
                assert.equal(0, userdn.length);
                done();
            },
            connection,
        );
    });

    it('invalid search filter', (t, done) => {
        const user = users[0];
        const pool = connection.server.notes.ldappool;
        pool.config.authn.searchfilter = '(&(objectclass=*)(uid=%u';
        plugin._get_dn_for_uid(
            user.uid,
            function (err, userdn) {
                assert.equal('unbalanced parens', err.message);
                assert.equal(undefined, userdn);
                done();
            },
            connection,
        );
    });

    it('invalid basedn', (t, done) => {
        const user = users[0];
        connection.server.notes.ldappool.config.basedn = 'invalid';
        plugin._get_dn_for_uid(
            user.uid,
            function (err, userdn) {
                assert.equal('InvalidDistinguishedNameError', err.name);
                assert.equal(undefined, userdn);
                done();
            },
            connection,
        );
    });

    it('no pool', (t, done) => {
        connection.server.notes.ldappool = undefined;
        const user = users[0];
        plugin._get_dn_for_uid(
            user.uid,
            function (err, userdn) {
                assert.equal('LDAP Pool not found!', err);
                assert.equal(undefined, userdn);
                done();
            },
            connection,
        );
    });
});

describe('check_plain_passwd', () => {
    beforeEach(_set_up);

    for (const user of users.slice(0, 2)) {
        it(`validates user ${user.uid}`, (t, done) => {
            plugin.check_plain_passwd(
                connection,
                user.uid,
                user.password,
                function (result) {
                    assert.equal(true, result);
                    done();
                },
            );
        });
    }

    for (const user of users.slice(2)) {
        it(`rejects user ${user.uid}`, (t, done) => {
            plugin.check_plain_passwd(
                connection,
                user.uid,
                user.password,
                function (result) {
                    assert.equal(false, result);
                    done();
                },
            );
        });
    }

    it(`rejects invalid user`, (t, done) => {
        plugin.check_plain_passwd(
            connection,
            'invalid',
            'invalid',
            function (result) {
                assert.equal(false, result);
                done();
            },
        );
    });

    for (const user of users) {
        it(`dn validates user ${user.uid}`, (t, done) => {
            connection.server.notes.ldappool.config.authn.dn = [
                'uid=%u,ou=users,dc=example,dc=com',
                'uid=%u,ou=people,dc=example,dc=com',
            ];
            plugin.check_plain_passwd(
                connection,
                user.uid,
                user.password,
                function (result) {
                    assert.strictEqual(true, result);
                    done();
                },
            );
        });
    }

    it(`dn rejects invalid user`, (t, done) => {
        connection.server.notes.ldappool.config.authn.dn = [
            'uid=%u,ou=users,dc=example,dc=com',
            'uid=%u,ou=people,dc=example,dc=com',
        ];
        plugin.check_plain_passwd(
            connection,
            'invalid',
            'invalid',
            function (result) {
                assert.equal(false, result);
                done();
            },
        );
    });
});
