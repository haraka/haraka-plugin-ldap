#!/bin/sh
# Bring up a throwaway slapd for CI (GitHub ubuntu-latest). Fails fast
# and loudly: a dead slapd must not degrade into a confusing "all the
# LDAP tests fail" run.
set -e

if ! dpkg -l | grep -q slapd; then
    echo "policy-rc.d status: blocking automatic service startup"
    sh -c "echo 'exit 101' > /usr/sbin/policy-rc.d"
    chmod +x /usr/sbin/policy-rc.d

    apt install --no-install-recommends -y gcc gettext make g++ apparmor-utils slapd ldap-utils ldapscripts netcat-openbsd

    echo "policy-rc.d status: unblocking service startup"
    rm -f /usr/sbin/policy-rc.d
fi

systemctl stop slapd 2>/dev/null || true
killall -9 slapd 2>/dev/null || true

# Ubuntu confines slapd to /etc/ldap, /var/lib/ldap, /var/run/slapd.
# This fixture runs slapd from the workspace with data in /tmp, so the
# enforced profile blocks startup. Put it in complain mode, and if that
# is unavailable, unload the profile entirely. Best-effort, but do not
# hide whether it actually took.
if command -v aa-complain >/dev/null 2>&1; then
    aa-complain /usr/sbin/slapd || apparmor_parser -R /etc/apparmor.d/usr.sbin.slapd 2>/dev/null || true
fi

sed -i -e '/^server/ s/:389$/:3389/' -e '/^server/ s/:636$/:3636/' config/ldap.ini

# Must match `directory` and `pidfile` in linux/slapd.conf exactly.
rm -rf /tmp/slapd
mkdir -p /tmp/slapd/db /tmp/slapd/run

# Pre-flight: validate the config (catches missing module / bad
# directory / schema path) and surface the real error before we even
# try to listen.
if ! slapd -Tt -f test/fixtures/linux/slapd.conf; then
    echo "ERROR: slapd config test failed (see above)" >&2
    exit 1
fi

diagnose_and_die() {
    echo "ERROR: slapd failed to start / is not listening on" \
        "127.0.0.1:3389. Re-running in the foreground:" >&2
    timeout 5 slapd -d 1 -f test/fixtures/linux/slapd.conf \
        -h "ldap://127.0.0.1:3389" 2>&1 | sed 's/^/  slapd: /' >&2 || true
    exit 1
}

# No -d: let slapd daemonize so it survives into the `npm test` step (a
# foreground/backgrounded slapd is reaped when this step's shell exits).
# `|| diagnose_and_die` (not bare) so `set -e` doesn't pre-empt the
# diagnostics; slapd's parent only returns 0 once listeners are open.
slapd -f test/fixtures/linux/slapd.conf \
    -h "ldap://127.0.0.1:3389 ldaps://127.0.0.1:3636" || diagnose_and_die

# Belt-and-braces: confirm it is actually accepting connections.
ready=
for _ in $(seq 1 15); do
    if nc -z 127.0.0.1 3389 2>/dev/null; then
        ready=1
        break
    fi
    echo "Waiting for slapd..."
    sleep 1
done
[ -n "$ready" ] || diagnose_and_die
echo "slapd is ready."

ldapadd -x -D "cn=admin,dc=example,dc=com" -w "rAR84,NZ=F" \
    -H ldap://127.0.0.1:3389 -f test/env/testdata.ldif
