'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')

const { escapeFilter, escapeDN } = require('../lib/escape')

describe('escapeFilter (RFC 4515)', () => {
  it('passes through plain ASCII unchanged', () => {
    assert.equal(escapeFilter('alice@example.com'), 'alice@example.com')
  })

  it('escapes the five reserved characters', () => {
    assert.equal(escapeFilter('a*b'), 'a\\2ab')
    assert.equal(escapeFilter('(foo)'), '\\28foo\\29')
    assert.equal(escapeFilter('back\\slash'), 'back\\5cslash')
    assert.equal(escapeFilter('nul\0'), 'nul\\00')
  })

  it('escapes every occurrence, not just the first', () => {
    assert.equal(escapeFilter('a*b*c'), 'a\\2ab\\2ac')
  })

  it('neutralises a filter-injection attempt', () => {
    const evil = '*)(uid=*'
    const filter = `(uid=${escapeFilter(evil)})`
    assert.equal(filter, '(uid=\\2a\\29\\28uid=\\2a)')
    // The closing ')' that would have escaped the uid= clause is now \29.
    assert.ok(!filter.includes('*)('), 'no bare injection sequence remains')
  })

  it('coerces non-strings via String()', () => {
    assert.equal(escapeFilter(42), '42')
    assert.equal(escapeFilter(true), 'true')
  })

  it('returns "" for null and undefined', () => {
    assert.equal(escapeFilter(null), '')
    assert.equal(escapeFilter(undefined), '')
  })
})

describe('escapeDN (RFC 4514)', () => {
  it('passes through plain ASCII unchanged', () => {
    assert.equal(escapeDN('alice'), 'alice')
  })

  it('escapes structural characters anywhere in the value', () => {
    assert.equal(escapeDN('a,b'), 'a\\,b')
    assert.equal(escapeDN('a+b'), 'a\\+b')
    assert.equal(escapeDN('a"b'), 'a\\"b')
    assert.equal(escapeDN('a;b'), 'a\\;b')
    assert.equal(escapeDN('a<b'), 'a\\<b')
    assert.equal(escapeDN('a>b'), 'a\\>b')
    assert.equal(escapeDN('a\\b'), 'a\\\\b')
    assert.equal(escapeDN('a=b'), 'a\\=b')
    assert.equal(escapeDN('a\0b'), 'a\\00b')
  })

  it('escapes leading # but not interior #', () => {
    assert.equal(escapeDN('#abc'), '\\#abc')
    assert.equal(escapeDN('a#b'), 'a#b')
  })

  it('escapes leading and trailing spaces only', () => {
    assert.equal(escapeDN(' abc'), '\\ abc')
    assert.equal(escapeDN('abc '), 'abc\\ ')
    assert.equal(escapeDN(' abc '), '\\ abc\\ ')
    assert.equal(escapeDN('a b c'), 'a b c')
  })

  it('neutralises a DN-injection attempt', () => {
    const evil = 'foo,ou=admins'
    const dn = `uid=${escapeDN(evil)},ou=users,dc=example,dc=com`
    assert.equal(dn, 'uid=foo\\,ou\\=admins,ou=users,dc=example,dc=com')
  })

  it('returns "" for null and undefined', () => {
    assert.equal(escapeDN(null), '')
    assert.equal(escapeDN(undefined), '')
  })
})
