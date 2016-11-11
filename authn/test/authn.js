'use strict';

var fixtures     = require('haraka-test-fixtures');
var ldappool     = require('haraka-plugin-ldap-pool');

// test user data as defined in testdata.ldif
var users = [
    {
        uid : 'user1',
        dn : 'uid=user1,ou=users,dc=my-domain,dc=com',
        password : 'ykaHsOzEZD',
        mail : 'user1@my-domain.com'
    },
    {
        uid : 'user2',
        dn : 'uid=user2,ou=people,dc=my-domain,dc=com',
        password : 'KQD9zs,LGv',
        mail : 'user2@my-domain.com'
    },
    {
        uid : 'nonunique',
        dn : 'uid=nonunique,ou=users,dc=my-domain,dc=com',
        password : 'CZVm3,BLlx',
        mail : 'nonunique1@my-domain.com'
    },
    {
        uid : 'nonunique',
        dn : 'uid=nonunique,ou=people,dc=my-domain,dc=com',
        password : 'LsBHDGorAh',
        mail : 'nonunique2@my-domain.com'
    }
];

var _set_up = function (done) {
    this.users = users;
    this.plugin = new fixtures.plugin('ldap-authn');
    this.plugin.cfg = { main : {} };
    this.connection = fixtures.connection.createConnection();
    this.plugin.init_ldap_authn(function(){}, {
        notes : {
            ldappool : new ldappool.LdapPool({
                binddn : this.users[0].dn,
                bindpw : this.users[0].password,
                basedn : 'dc=my-domain,dc=com'
            })
        }
    });
    done();
};

exports.verify_user = {
    setUp : _set_up,
    'verify test data' : function(test) {
        test.expect(this.users.length);
        var plugin = this.plugin;
        var counter = 0;
        var testUser = function(result) {
            test.equals(true, result);
            counter++;
            if (counter === users.length) {
                test.done();
            }
        };
        var users = this.users;
        this.users.forEach(function(user) {
            plugin._verify_user(user.dn, user.password, testUser);
        });
    },
    'safety check: wrong password fails' : function(test) {
        test.expect(1);
        this.plugin._verify_user(this.users[0].dn, 'wrong', function(ok) {
            test.equals(false, ok);
            test.done();
        });
    },
    'safety check: invalid dn fails' : function(test) {
        test.expect(1);
        this.plugin._verify_user('wrong', 'wrong', function(ok) {
            test.equals(false, ok);
            test.done();
        });
    },
    'no pool' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        plugin.pool = undefined;
        var user = this.users[0];
        plugin._verify_user(user.dn, user.password, function(result) {
            test.equals(false, result);
            test.done();
        });
    }
};

exports._get_search_conf = {
    setUp : _set_up,
    'get defaults' : function(test) {
        test.expect(4);
        var opts = this.plugin._get_search_conf('testUid');
        test.equals(opts.basedn, this.plugin.pool.config.basedn);
        test.equals(opts.filter, '(&(objectclass=*)(uid=testUid))');
        test.equals(opts.scope, this.plugin.pool.config.scope);
        test.equals(opts.attributes.toString(), ['dn'].toString());
        test.done();
    },
    'get userdef' : function(test) {
        this.plugin.cfg.main.basedn = 'hop around as you like';
        this.plugin.cfg.main.searchfilter = '(&(objectclass=posixAccount)(uid=%u))';
        this.plugin.cfg.main.scope = 'one two three';
        test.expect(4);
        var opts = this.plugin._get_search_conf('testUid');
        test.equals(opts.basedn, 'hop around as you like');
        test.equals(opts.filter, '(&(objectclass=posixAccount)(uid=testUid))');
        test.equals(opts.scope, 'one two three');
        test.equals(opts.attributes.toString(), ['dn'].toString());
        test.done();
    }
};

exports.get_dn_for_uid = {
    setUp : _set_up,
    'user 1 dn2uid' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        var user = this.users[0];
        plugin._get_dn_for_uid(user.uid, function (err, userdn) {
            test.equals(null, err);
            test.equals(userdn.toString(), user.dn);
            test.done();
        });
    },
    'nonunique dn2uid' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        plugin._get_dn_for_uid('nonunique', function (err, userdn) {
            test.equals(null, err);
            test.equals(2, userdn.length);
            test.done();
        });
    },
    'invalid uid' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        plugin._get_dn_for_uid('doesntexist', function (err, userdn) {
            test.equals(null, err);
            test.equals(0, userdn.length);
            test.done();
        });
    },
    'invalid search filter' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        var user = this.users[0];
        plugin.cfg.main.searchfilter = '(&(objectclass=*)(uid=%u';
        plugin._get_dn_for_uid(user.uid, function (err, userdn) {
            test.equals('Error: (uid=user has unbalanced parentheses', err.toString());
            test.equals(undefined, userdn);
            test.done();
        });
    },
    'invalid basedn' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        var user = this.users[0];
        plugin.pool.config.basedn = 'invalid';
        plugin._get_dn_for_uid(user.uid, function (err, userdn) {
            test.equals('InvalidDistinguishedNameError', err.name);
            test.equals(undefined, userdn);
            test.done();
        });
    },
    'no pool' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        plugin.pool = undefined;
        var user = this.users[0];
        plugin._get_dn_for_uid(user.uid, function (err, userdn) {
            test.equals('LDAP Pool not found!', err);
            test.equals(undefined, userdn);
            test.done();
        });
    }
};

exports.hook_capabilities = {
    setUp : _set_up,
    'no tls no auth' : function(test) {
        var cb = function (rc, msg) {
            test.expect(1);
            test.ok(this.connection.capabilities.length === 0);
            test.done();
        }.bind(this);
        this.connection.using_tls = false;
        this.connection.capabilities = [];
        this.plugin.hook_capabilities(cb, this.connection);
    },
    'tls ante portas, ready for auth login' : function(test) {
        var cb = function (rc, msg) {
            test.expect(4);
            test.ok(this.connection.notes.allowed_auth_methods.length === 2);
            test.ok(this.connection.notes.allowed_auth_methods[0] === 'PLAIN');
            test.ok(this.connection.notes.allowed_auth_methods[1] === 'LOGIN');
            test.ok(this.connection.capabilities[0] === 'AUTH PLAIN LOGIN');
            test.done();
        }.bind(this);
        this.connection.using_tls = true;
        this.connection.capabilities = [];
        this.plugin.hook_capabilities(cb, this.connection);
    }
};

exports.register = {
    setUp : _set_up,
    'set master and child hooks to gain pool access' : function(test) {
        test.expect(5);
        test.equals(false, this.plugin.register_hook.called);
        this.plugin.register();
        test.equals('init_master', this.plugin.register_hook.args[0][0]);
        test.equals('init_child', this.plugin.register_hook.args[1][0]);
        test.equals('init_ldap_authn', this.plugin.register_hook.args[0][1]);
        test.equals('init_ldap_authn', this.plugin.register_hook.args[1][1]);
        test.done();
    },
    'load configuration file' : function(test) {
        var plugin = this.plugin;
        test.expect(2);
        this.plugin.register();
        test.equals('sub', plugin.cfg.main.scope);
        test.equals('(&(objectclass=*)(uid=%u))', plugin.cfg.main.searchfilter);
        test.done();
    }
};

exports.init_ldap_authn = {
    setUp : _set_up,
    'call next' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function() {
            test.ok(true);
            test.done();
        };
        plugin.init_ldap_authn(callback, { notes : { ldappool : {} } });
    },
    'no pool' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        plugin.pool = undefined;
        var callback = function() {
            test.equals(undefined, plugin.pool);
            test.done();
        };
        plugin.init_ldap_authn(callback, { notes : { } });
    }
};

exports.check_plain_passwd = {
    setUp : _set_up,
    'search with test users and invalid user' : function(test) {
        test.expect(5);
        var plugin = this.plugin;
        var users = this.users;
        var connection = this.connection;
        plugin.check_plain_passwd(connection, users[0].uid, users[0].password, function(result) {
            test.equals(true, result);
            plugin.check_plain_passwd(connection, users[1].uid, users[1].password, function(result) {
                test.equals(true, result);
                plugin.check_plain_passwd(connection, users[2].uid, users[2].password, function(result) {
                    test.equals(false, result);
                    plugin.check_plain_passwd(connection, users[3].uid, users[3].password, function(result) {
                        test.equals(false, result);
                        plugin.check_plain_passwd(connection, 'invalid', 'invalid', function(result) {
                            test.equals(false, result);
                            test.done();
                        });
                    });
                });
            });
        });
    },
    'try dn with test users and invalid user' : function(test) {
        test.expect(5);
        var plugin = this.plugin;
        var connection = this.connection;
        plugin.cfg.main.dn = [ 'uid=%u,ou=users,dc=my-domain,dc=com',
                               'uid=%u,ou=people,dc=my-domain,dc=com' ];
        plugin.check_plain_passwd(connection, users[0].uid, users[0].password, function(result) {
            test.equals(true, result);
            plugin.check_plain_passwd(connection, users[1].uid, users[1].password, function(result) {
                test.equals(true, result);
                plugin.check_plain_passwd(connection, users[2].uid, users[2].password, function(result) {
                    test.equals(true, result);
                    plugin.check_plain_passwd(connection, users[3].uid, users[3].password, function(result) {
                        test.equals(true, result);
                        plugin.check_plain_passwd(connection, 'invalid', 'invalid', function(result) {
                            test.equals(false, result);
                            test.done();
                        });
                    });
                });
            });
        });
    }
};
