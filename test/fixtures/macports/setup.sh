#!/bin/sh

set -e

/usr/bin/sed -i.bak -e '/^server/ s/:389/:3389/' -e '/^server/ s/:636/:3636/' test/config/ldap.ini
if [ -d "/var/tmp/slapd" ]; then rm -rf /var/tmp/slapd; fi
if [ ! -d /var/run/slapd ]; then mkdir /var/run/slapd; fi
mkdir /var/tmp/slapd

if [ ! -x /opt/local/sbin/slapadd ]; then
	sudo port install openldap
fi

/opt/local/sbin/slapadd -n 0 -F /var/tmp/slapd -l test/fixtures/macports/slapd.ldif

/opt/local/libexec/slapd -f test/fixtures/macports/slapd.conf -h "ldap://localhost:3389 ldaps://localhost:3636" &
sleep 3

/opt/local/bin/ldapadd -x -D "cn=admin,dc=example,dc=com" -w "rAR84,NZ=F" -H ldap://localhost:3389 -f test/env/testdata.ldif
