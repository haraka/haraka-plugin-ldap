# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

- test: refactored against test-fixtures 1.7.0

### [1.2.1] - 2026-05-24

- refactor: migrate internals to async/await, internal \_methods return promises
- fix(security): escape filter values per RFC 4515 and DN values per RFC 4514
- fix(pool): only add client to pool on successful bind
- fix(pool): await unbind() in close() so next() runs after all clients are closed
- doc(README): clarify tls_rejectUnauthorized default
- config: replace sample bindpw with placeholder

### [1.2.0] - 2026-05-24

- dep(ldapjs): update to v3
- dep(address-rfc2821): replaced with @haraka/email-address
- test: runner is now node:test

### [1.1.4] - 2025-01-26

- prettier: move config into package.json
- dep(eslint): upgrade to v9

### [1.1.3] - 2024-08-23

- fix: always unbind after bind, fixes #12
- dep: eslint-plugin-haraka -> @haraka/eslint-config
- chore: populate [files] in package.json. Delete .npmignore.
- lint: remove duplicate / stale rules from .eslintrc
- chore: prettier automated code formatting
- doc: add CONTRIBUTORS.md

### [1.1.2] - 2024-03-15

- ci: customized publish script

#### 1.1.1 - 2024-03-15

- config: comment out default server entries, fixes #9
- doc(README): update doc badge URL #8
- test: skip pool shutdown test, it interferes with other tests
- ci: update tests to use LTS node versions
- test: improve macports setup script

#### 1.1.0 - 2023-04-26

- authn: replace async.detect with local fn
- aliases: replace async with Promise.all
- dep(async): removed
- dep(ldapjs): update from 1.0.2 to 2.3.3
- noop: remove useless returns
- es6: more arrow functions
- style: inline use of `plugin`
- ci: switch travis -> GHA
- ci: enable codeql
- test: use RFC example.com for test domain
- test: refactored some to improve error messages
- test: add fixtures for setting up slapd on macosx and linux
- doc(README): update with GHA badge

#### 1.0.2 - 2017-09-30

- check_rcpt must return next(ok) if a valid recipient was found

#### 1.0.2 - 2016-12-10

- test get_alias for resolve-by-dn case
- added debug log to \_resolve_dn_to_alias
- fixed wrong default attribute there
- include all ops in config

[1.1.0]: https://github.com/haraka/haraka-plugin-ldap/releases/tag/v1.1.0
[1.1.1]: https://github.com/haraka/haraka-plugin-ldap/releases/tag/1.1.1
[1.1.2]: https://github.com/haraka/haraka-plugin-ldap/releases/tag/v1.1.2
[1.1.3]: https://github.com/haraka/haraka-plugin-ldap/releases/tag/v1.1.3
[1.1.4]: https://github.com/haraka/haraka-plugin-ldap/releases/tag/v1.1.4
[1.2.0]: https://github.com/haraka/haraka-plugin-ldap/releases/tag/v1.2.0
[1.2.1]: https://github.com/haraka/haraka-plugin-ldap/releases/tag/v1.2.1
