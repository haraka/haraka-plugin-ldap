'use strict';

var util = require('util');


exports._verify_existence = function (address, callback, connection) {
    var plugin = this;
    var pool = connection.server.notes.ldappool;
    var onError = function(err) {
        connection.logerror('Could not verify address "' + address + '": ' +  err);
        callback(err, false);
    };
    if (!pool) {
        return onError('LDAP Pool not found!');
    }
    var search = function (err, client) {
        if (err) {
            return onError(err);
        }
        else {
            var config = plugin._get_search_conf(address, connection);
            connection.logdebug('Verifying existence: ' + util.inspect(config));
            try {
                client.search(config.basedn, config, function(search_error, res) {
                    if (search_error) { onError(search_error); }
                    var entries = 0;
                    res.on('searchEntry', function(entry) {
                        entries++;
                    });
                    res.on('error', onError);
                    res.on('end', function() {
                        callback(null, entries > 0);
                    });
                });
            }
            catch (e) {
                return onError(e);
            }
        }
    };
    pool.get(search);
};

exports._get_search_conf = function(address, connection) {
    var plugin = this;
    var pool = connection.server.notes.ldappool;
    var filter = pool.config.rcpt_to.searchfilter || '(&(objectclass=*)(mail=%a))';
    filter = filter.replace(/%a/g, address);
    var config = {
        basedn: pool.config.rcpt_to.basedn || pool.config.basedn,
        filter: filter,
        scope: pool.config.rcpt_to.scope || pool.config.scope,
        attributes: [ 'dn' ]
    };
    if (config.basedn === undefined) {
        plugin.logerror('Undefined basedn. Please check your configuration!');
    }
    return config;
};

exports.register = function() {
    var plugin = this;
    plugin.register_hook('rcpt', 'check_rcpt');
};

exports.check_rcpt = function(next, connection, params) {
    var plugin = this;
    if (!params || !params[0] || !params[0].address) {
        connection.logerror('Ignoring invalid call. Given connection.transaction:' +
                            util.inspect(connection.transaction));
        return next();
    }
    var rcpt   = params[0].address();
    var callback = function(err, result) {
        if (err) {
            connection.logerror('Could not use LDAP for address check: ' + err);
            next(DENYSOFT);
        }
        else if (!result) {
            next(DENY);
        }
        else {
            next(OK);
        }
    };
    plugin._verify_existence(rcpt, callback, connection);
};