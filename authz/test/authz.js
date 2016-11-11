'use strict';

var fixtures     = require('haraka-test-fixtures');
var ldappool     = require('haraka-plugin-ldap-pool');
var Address      = require('address-rfc2821').Address;


var _set_up = function (done) {
    this.user = {
        uid : 'user1',
        dn : 'uid=user1,ou=users,dc=my-domain,dc=com',
        password : 'ykaHsOzEZD',
        mail : 'user1@my-domain.com'
    };
    this.plugin = new fixtures.plugin('ldap-authz');
    this.plugin.cfg = { main : { } };
    this.connection = fixtures.connection.createConnection();
    this.plugin.init_ldap_authz(function(){}, {
        notes : {
            ldappool : new ldappool.LdapPool({
                binddn : this.user.dn,
                bindpw : this.user.password,
                basedn : 'dc=my-domain,dc=com'
            })
        }
    });
    this.plugin.cfg.main.searchfilter =  '(&(objectclass=*)(uid=%u)(mailLocalAddress=%a))';
    done();
};

exports._verify_address = {
    setUp : _set_up,
    '1 entry' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        var user = this.user;
        plugin._verify_address(user.uid, user.mail, function(err, result) {
            test.equals(true, result);
            test.done();
        });
    },
    '0 entries' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        plugin._verify_address('alien', 'unknown', function(err, result) {
            test.equals(false, result);
            test.done();
        });
    },
    '2 entries' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        plugin.cfg.main.searchfilter =  '(&(objectclass=*)(|(uid=%u)(uid=user2)))';
        plugin._verify_address('user1', 'who cares', function(err, result) {
            test.equals(true, result);
            test.done();
        });
    },
    'invalid search filter' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        var user = this.user;
        plugin.cfg.main.searchfilter =  '(&(objectclass=*)(|(uid=%u';
        plugin._verify_address(user.uid, user.mail, function(err, result) {
            test.equals('Error: (|(uid=user has unbalanced parentheses', err.toString());
            test.equals(false, result);
            test.done();
        });
    },
    'no pool' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        plugin.pool = undefined;
        var user = this.user;
        plugin._verify_address(user.uid, user.mail, function (err, userdn) {
            test.equals('LDAP Pool not found!', err);
            test.equals(false, userdn);
            test.done();
        });
    }
};

exports._get_search_conf = {
    setUp : _set_up,
    'get defaults' : function(test) {
        test.expect(4);
        var opts = this.plugin._get_search_conf('testUid', 'testMail');
        test.equals(opts.basedn, this.plugin.pool.config.basedn);
        test.equals(opts.filter, '(&(objectclass=*)(uid=testUid)(mailLocalAddress=testMail))');
        test.equals(opts.scope, this.plugin.pool.config.scope);
        test.equals(opts.attributes.toString(), ['dn'].toString());
        test.done();
    },
    'get userdef' : function(test) {
        this.plugin.cfg.main.basedn = 'hop around as you like';
        this.plugin.cfg.main.searchfilter = '(&(objectclass=posixAccount)(uid=%u)(mail=%a))';
        this.plugin.cfg.main.scope = 'one two three';
        test.expect(4);
        var opts = this.plugin._get_search_conf('testUid', 'testMail');
        test.equals(opts.basedn, 'hop around as you like');
        test.equals(opts.filter, '(&(objectclass=posixAccount)(uid=testUid)(mail=testMail))');
        test.equals(opts.scope, 'one two three');
        test.equals(opts.attributes.toString(), ['dn'].toString());
        test.done();
    }
};

exports.register = {
    setUp : _set_up,
    'set master and child hooks to gain pool access' : function(test) {
        test.expect(7);
        test.equals(false, this.plugin.register_hook.called);
        this.plugin.register();
        test.equals('init_master', this.plugin.register_hook.args[0][0]);
        test.equals('init_child', this.plugin.register_hook.args[1][0]);
        test.equals('mail', this.plugin.register_hook.args[2][0]);
        test.equals('init_ldap_authz', this.plugin.register_hook.args[0][1]);
        test.equals('init_ldap_authz', this.plugin.register_hook.args[1][1]);
        test.equals('check_authz', this.plugin.register_hook.args[2][1]);
        test.done();
    },
    'load configuration file' : function(test) {
        var plugin = this.plugin;
        test.expect(2);
        this.plugin.register();
        test.equals('sub', plugin.cfg.main.scope);
        test.equals('(&(objectclass=*)(uid=%u)(mailLocalAddress=%a))', plugin.cfg.main.searchfilter);
        test.done();
    }
};

exports.init_ldap_authz = {
    setUp : _set_up,
    'call next' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function() {
            test.ok(true);
            test.done();
        };
        plugin.init_ldap_authz(callback, { notes : { ldappool : {} } });
    },
    'no pool' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        plugin.pool = undefined;
        var callback = function() {
            test.equals(undefined, plugin.pool);
            test.done();
        };
        plugin.init_ldap_authz(callback, { notes : { } });
    }
};

exports.check_authz = {
    setUp : _set_up,
    'ok' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(undefined, err);
            test.done();
        };
        this.connection.notes = { auth_user : 'user1' };
        plugin.check_authz(callback, this.connection, [new Address('<user1@my-domain.com>')]);
    },
    'deny if not authorized' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(DENY, err);
            test.done();
        };
        this.connection.notes = { auth_user : 'user1' };
        plugin.check_authz(callback, this.connection, [new Address('user2@my-domain.com')]);
    },
    'denysoft on error' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(DENYSOFT, err);
            test.done();
        };
        plugin.cfg.main.searchfilter =  '(&(objectclass=*)(|(uid=%u';
        this.connection.notes = { auth_user : 'user1' };
        plugin.check_authz(callback, this.connection, [new Address('user1@my-domain.com')]);
    },
    'ignore invalid params: missing auth_user' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(undefined, err);
            test.done();
        };
        plugin.check_authz(callback, this.connection, [new Address('user1@my-domain.com')]);
    },
    'ignore invalid params: missing address' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(undefined, err);
            test.done();
        };
        plugin.check_authz(callback, this.connection);
    }
};