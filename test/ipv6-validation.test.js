'use strict'

const test = require('tape')
const fastURI = require('..')

const HOST_ERROR = 'URI host is malformed.'

// U+212A KELVIN SIGN. It is not an ASCII letter, so it is neither a valid
// IPvFuture character nor a valid zone character, yet String#toLowerCase maps
// it to "k": accepting it would let a rejected literal case-fold into a
// different, valid-looking host. Named rather than inlined so it stays
// distinguishable from an ASCII "K" in the cases below.
const KELVIN = 'K'

const malformedLiterals = [
  '::not-valid',
  'fc00::not-hex',
  'fe80::not-hex',
  '1:2:3',
  '1:2:3:4:5:6:7',
  '1:2:3:4:5:6:7:8:9',
  '1::2::3',
  '1:::2',
  ':::1',
  '12345::',
  '1:2:3:4:5:6:7::8',
  '::ffff:192.0.2.999',
  '::ffff:192.0.2',
  '::ffff:192.168.001.1',
  '::192.0.2.1:1',
  '1:2:3:4:5:192.0.2.1::',
  'v.foo',
  'v1.',
  'v1.foo%25bar',
  'v1.' + KELVIN,
  'fe80::1%25',
  'fe80::1%25eth 0',
  'fe80::1%25eth%ZZ',
  'fe80::1%25' + KELVIN,
  'not-an-ip'
]

test('malformed bracketed IP literals fail without being rewritten', (t) => {
  for (const literal of malformedLiterals) {
    const uri = `http://[${literal}]/private`
    const parsed = fastURI.parse(uri)

    t.equal(parsed.error, HOST_ERROR, `parse rejects ${literal}`)
    t.equal(parsed.host, `[${literal.toLowerCase()}]`, `parse does not truncate ${literal}`)
    t.equal(fastURI.normalize(uri), uri, `normalize preserves ${literal}`)
    t.equal(fastURI.equal(uri, uri), false, `equal rejects ${literal}`)
  }
  t.end()
})

test('resolve throws for malformed bracketed IP literals', (t) => {
  for (const literal of malformedLiterals) {
    const uri = `http://[${literal}]/private`

    t.throws(
      () => fastURI.resolve(uri, 'child'),
      /URI host is malformed\./,
      `rejects malformed base ${literal}`
    )
    t.throws(
      () => fastURI.resolve('http://example.com/', uri),
      /URI host is malformed\./,
      `rejects malformed relative input ${literal}`
    )
  }
  t.end()
})

// A host is an IP-literal only when the *whole* component is bracketed. A host
// carrying a stray or unterminated bracket is not a literal and is not a valid
// reg-name either, so it must be rejected outright: otherwise it slips past the
// literal validation entirely and reaches the IDN canonicalization, where a
// lenient URL parser can repair it into a different, attacker-chosen host.
const strayBracketHosts = [
  ['http://[evil.com/private', '[evil.com'],
  ['http://evil.com]/private', 'evil.com]'],
  ['http://ev[il.com/private', 'ev[il.com'],
  ['http://ev]il.com/private', 'ev]il.com'],
  ['//[evil.com/private', '[evil.com'],
  ['//evil.com]/private', 'evil.com]'],
  ['foo://[evil.com/private', '[evil.com'],
  ['foo://evil.com]/private', 'evil.com]'],
  ['http://[[::1]/private', '[[::1]'],
  ['http://user@[@127.0.0.1:8123/admin', '[@127.0.0.1'],
  ['http://user@]127.0.0.1:8123/admin', ']127.0.0.1'],
  ['http://user@prefix[@127.0.0.1:8123/admin', 'prefix[@127.0.0.1'],
  ['http://user@prefix]@127.0.0.1:8123/admin', 'prefix]@127.0.0.1']
]

test('hosts with a stray IP-literal bracket are rejected, not repaired', (t) => {
  for (const [uri, host] of strayBracketHosts) {
    const parsed = fastURI.parse(uri)

    t.equal(parsed.error, HOST_ERROR, `parse rejects ${uri}`)
    t.equal(parsed.host, host, `parse does not rewrite the host of ${uri}`)
    t.equal(fastURI.normalize(uri), uri, `normalize preserves ${uri}`)
    t.equal(fastURI.equal(uri, uri), false, `equal rejects ${uri}`)
    t.throws(
      () => fastURI.resolve(uri, 'child'),
      /URI host is malformed\./,
      `resolve rejects the base ${uri}`
    )
    t.throws(
      () => fastURI.resolve('http://example.com/', uri),
      /URI host is malformed\./,
      `resolve rejects the relative input ${uri}`
    )
  }
  t.end()
})

test('unterminated IP literals never resolve to a usable URI', (t) => {
  // These split differently in the URI grammar (the unclosed "[" leaves a
  // colon in the path), so the exact error differs, but the URI must still be
  // rejected and must never be canonicalized into a different valid URI.
  const unterminated = [
    'http://[fe80::1/private',
    'http://fe80::1]/private',
    'http://[fe80::1%25eth0/private'
  ]

  for (const uri of unterminated) {
    const parsed = fastURI.parse(uri)

    t.ok(parsed.error, `parse rejects ${uri}`)
    t.equal(fastURI.normalize(uri), uri, `normalize preserves ${uri}`)
    t.equal(fastURI.equal(uri, uri), false, `equal rejects ${uri}`)
    t.throws(() => fastURI.resolve(uri, 'child'), `resolve rejects the base ${uri}`)
    t.throws(() => fastURI.resolve('http://example.com/', uri), `resolve rejects the relative input ${uri}`)
  }
  t.end()
})

test('valid IPv6, IPvFuture, embedded IPv4, and zone forms normalize safely', (t) => {
  const cases = [
    ['http://[::]/', 'http://[::]/', '::'],
    ['http://[::1]/', 'http://[::1]/', '::1'],
    ['http://[1::]/', 'http://[1::]/', '1::'],
    ['http://[2001:0DB8::0001]/', 'http://[2001:db8::1]/', '2001:db8::1'],
    ['http://[0:0:0:0:0:0:0:0]/', 'http://[::]/', '::'],
    ['http://[::ffff:192.0.2.1]/', 'http://[::ffff:192.0.2.1]/', '::ffff:192.0.2.1'],
    ['http://[1:2:3:4:5:6:192.0.2.1]/', 'http://[1:2:3:4:5:6:192.0.2.1]/', '1:2:3:4:5:6:192.0.2.1'],
    ['http://[fe80::A%25EN1]/', 'http://[fe80::a%25EN1]/', 'fe80::a%EN1'],
    ['http://[fe80::a%en1]/', 'http://[fe80::a%25en1]/', 'fe80::a%en1'],
    ['http://[fe80::a%25eth%2D0]/', 'http://[fe80::a%25eth%2D0]/', 'fe80::a%eth%2D0'],
    ['http://[v1.example]/', 'http://[v1.example]/', '[v1.example]'],
    ['http://[vF.A:b]/', 'http://[vf.a:b]/', '[vf.a:b]']
  ]

  for (const [uri, normalized, host] of cases) {
    const parsed = fastURI.parse(uri)
    t.equal(parsed.error, undefined, `${uri} parses without error`)
    t.equal(parsed.host, host, `${uri} has the expected host`)
    t.equal(fastURI.normalize(uri), normalized, `${uri} normalizes safely`)
  }
  t.end()
})
