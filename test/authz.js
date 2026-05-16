'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert');

const fixtures = require('haraka-test-fixtures');
const Address = require('@haraka/email-address').Address;
const constants = require('haraka-constants');
const ldappool = require('../pool');

let user, plugin, connection;

function _set_up(t, done) {
    user = {
        uid: 'user1',
        dn: 'uid=user1,ou=users,dc=example,dc=com',
        password: 'ykaHsOzEZD',
        mail: 'user1@example.com',
    };
    plugin = require('../authz');
    connection = fixtures.connection.createConnection();
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
    };
    connection.server.notes.ldappool.config.authz = {
        searchfilter: '(&(objectclass=*)(uid=%u)(mailLocalAddress=%a))',
    };
    done();
}

describe('_verify_address', () => {
    beforeEach(_set_up);

    it('1 entry', (t, done) => {
        plugin._verify_address(
            user.uid,
            user.mail,
            function (err, result) {
                assert.equal(true, result);
                done();
            },
            connection,
        );
    });

    it('0 entries', (t, done) => {
        plugin._verify_address(
            'alien',
            'unknown',
            function (err, result) {
                assert.ifError(err);
                assert.equal(false, result);
                done();
            },
            connection,
        );
    });

    it('2 entries', (t, done) => {
        const pool = connection.server.notes.ldappool;
        pool.config.authz.searchfilter = '(&(objectclass=*)(|(uid=%u)(uid=user2)))';
        plugin._verify_address(
            'user1',
            'who cares',
            function (err, result) {
                assert.ifError(err);
                assert.equal(true, result);
                done();
            },
            connection,
        );
    });

    it('invalid search filter', (t, done) => {
        const pool = connection.server.notes.ldappool;
        pool.config.authz.searchfilter = '(&(objectclass=*)(|(uid=%u';
        plugin._verify_address(
            user.uid,
            user.mail,
            function (err, result) {
                assert.equal('unbalanced parentheses', err.message);
                assert.equal(false, result);
                done();
            },
            connection,
        );
    });

    it('no pool', (t, done) => {
        connection.server.notes.ldappool = undefined;
        plugin._verify_address(
            user.uid,
            user.mail,
            function (err, userdn) {
                assert.equal('LDAP Pool not found!', err);
                assert.equal(false, userdn);
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
        const opts = plugin._get_search_conf('testUid', 'testMail', connection);
        assert.equal(opts.basedn, pool.config.basedn);
        assert.equal(
            opts.filter,
            '(&(objectclass=*)(uid=testUid)(mailLocalAddress=testMail))',
        );
        assert.equal(opts.scope, pool.config.scope);
        assert.equal(opts.attributes.toString(), ['dn'].toString());
        done();
    });

    it('get userdef', (t, done) => {
        const pool = connection.server.notes.ldappool;
        pool.config.authz.basedn = 'hop around as you like';
        pool.config.authz.searchfilter =
      '(&(objectclass=posixAccount)(uid=%u)(mail=%a))';
        pool.config.authz.scope = 'one two three';
        const opts = plugin._get_search_conf('testUid', 'testMail', connection);
        assert.equal(opts.basedn, 'hop around as you like');
        assert.equal(
            opts.filter,
            '(&(objectclass=posixAccount)(uid=testUid)(mail=testMail))',
        );
        assert.equal(opts.scope, 'one two three');
        assert.equal(opts.attributes.toString(), ['dn'].toString());
        done();
    });
});

describe('check_authz', () => {
    beforeEach(_set_up);

    it('ok', (t, done) => {
        connection.notes = { auth_user: 'user1' };
        plugin.check_authz(
            function (err) {
                assert.equal(undefined, err);
                done();
            },
            connection,
            [new Address('<user1@example.com>')],
        );
    });

    it('deny if not authorized', (t, done) => {
        connection.notes = { auth_user: 'user1' };
        plugin.check_authz(
            function (err) {
                assert.equal(constants.deny, err);
                done();
            },
            connection,
            [new Address('user2@example.com')],
        );
    });

    it('denysoft on error', (t, done) => {
        connection.server.notes.ldappool.config.authz.searchfilter =
      '(&(objectclass=*)(|(uid=%u';
        connection.notes = { auth_user: 'user1' };
        plugin.check_authz(
            function (err) {
                assert.equal(constants.denysoft, err);
                done();
            },
            connection,
            [new Address('user1@example.com')],
        );
    });

    it('ignore invalid params: missing auth_user', (t, done) => {
        plugin.check_authz(
            function (err) {
                assert.ifError(err);
                done();
            },
            connection,
            [new Address('user1@example.com')],
        );
    });

    it('ignore invalid params: missing address', (t, done) => {
        plugin.check_authz(function (err) {
            assert.ifError(err);
            done();
        }, connection);
    });
});
