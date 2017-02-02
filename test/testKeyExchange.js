"use strict"
const assert = require('assert')
const crypto = require('crypto')
const ec_pem = require('../ec_pem')

const curve = 'secp521r1'
const keys = {
  priv: ['-----BEGIN EC PRIVATE KEY-----',
         'ME8CAQEEQYEYjwI7+EZlaLR9bVFluK0Jv57LFl+EgDdvCabqjUuW2IhxGC4ZylGd',
         'Imp8OMoAUU1n7IGlDNmXZ5Ui0qdfvPlEoAcGBSuBBAAj',
         '-----END EC PRIVATE KEY-----'].join('\n'),
  pub:  ['-----BEGIN PUBLIC KEY-----',
         'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBnFjGRSIqN/aqVGXkdAor3XkHkdbz',
         'Q6xpwePa0+9dvNLzCUUrx69rhu2eP4amhyjshEK3UrJamjarUGboCaMYuqYBHIfh',
         'u5sSi+Uen8SvRrJBh2nzHHlEiBsRWJ1C/pNxpnpTEfyJr+15nWF93OCl4hLZJZ+W',
         '7V2nmFPxLdo4iPr4rJ4=',
         '-----END PUBLIC KEY-----'].join('\n'),
}

describe('test key exchange', () => {
  it('should work', () => {
    const alice = crypto.createECDH(curve)
    alice.generateKeys()

    const bob = ec_pem.loadPrivateKey(keys.priv)
    const bob_secret = bob.computeSecret(alice.getPublicKey('hex'), 'hex', 'hex')

    const bob_key = ec_pem.loadPublicKey(keys.pub, 'hex')
    const alice_secret = alice.computeSecret(bob_key.public_key, 'hex', 'hex')

    assert.equal(bob_secret, alice_secret)

    const bob_key_ec = ec_pem.loadPublicKey(keys.pub)
    const alice_secret_ec = alice.computeSecret(bob_key_ec.getPublicKey())

    assert.equal(bob_secret, alice_secret_ec.toString('hex'))

    assert.equal(bob_key.public_key, bob.getPublicKey('hex'))
    assert.equal(bob_key_ec.getPublicKey('hex'), bob.getPublicKey('hex'))

  })
})

describe('test key store/load/clone roundtrips', () => {
  let bob_private, bob_public
  before(() => {
    bob_private = ec_pem.loadPrivateKey(keys.priv)
    bob_public = ec_pem.loadPublicKey(keys.pub)
  })

  it('should round trip private_key through Base64', () =>
    assert.deepEqual(
      ec_pem.fromBase64(bob_private.toBase64()).toJSON(),
      {curve, private_key: ec_pem.asUrlSafeBase64(bob_private.getPrivateKey('base64'))}) )

  it('should round trip public_key through Base64', () =>
    assert.deepEqual(
      ec_pem.fromBase64(bob_public.toBase64()).toJSON(),
      {curve, public_key: ec_pem.asUrlSafeBase64(bob_public.getPublicKey('base64'))}) )

  it('should round load private_key from Base64', () =>
    assert.deepEqual(
      ec_pem.load(bob_private.toBase64()).toJSON(),
      {curve, private_key: ec_pem.asUrlSafeBase64(bob_private.getPrivateKey('base64'))}) )

  it('should round load public_key from Base64', () =>
    assert.deepEqual(
      ec_pem.load(bob_public.toBase64()).toJSON(),
      {curve, public_key: ec_pem.asUrlSafeBase64(bob_public.getPublicKey('base64'))}) )

  it('should round trip private_key through JSON', () =>
    assert.deepEqual(
      ec_pem.fromJSON(JSON.parse(JSON.stringify(bob_private))).toJSON(),
      {curve, private_key: ec_pem.asUrlSafeBase64(bob_private.getPrivateKey('base64'))}) )

  it('should round trip public_key through JSON', () =>
    assert.deepEqual(
      ec_pem.fromJSON(JSON.parse(JSON.stringify(bob_public))).toJSON(),
      {curve, public_key: ec_pem.asUrlSafeBase64(bob_public.getPublicKey('base64'))}) )

  it('should round load private_key from JSON', () =>
    assert.deepEqual(
      ec_pem.load(JSON.parse(JSON.stringify(bob_private))).toJSON(),
      {curve, private_key: ec_pem.asUrlSafeBase64(bob_private.getPrivateKey('base64'))}) )

  it('should round load public_key from JSON', () =>
    assert.deepEqual(
      ec_pem.load(JSON.parse(JSON.stringify(bob_public))).toJSON(),
      {curve, public_key: ec_pem.asUrlSafeBase64(bob_public.getPublicKey('base64'))}) )

  it('should clone properly', () => {
    assert.deepEqual(bob_public.toJSON(), bob_public.clone().toJSON())
    assert.deepEqual(bob_public.toJSON(), bob_private.clone('public').toJSON())
    assert.deepEqual(bob_private.toJSON(), bob_private.clone().toJSON())
  })

  it('should clone public properly', () =>
    assert.deepEqual(bob_public.toJSON(), bob_private.clone('public').toJSON()) )

  it('should clone private properly', () =>
    assert.deepEqual(bob_private.toJSON(), bob_private.clone('private').toJSON()) )
})
