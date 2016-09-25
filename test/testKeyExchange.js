"use strict"
const assert = require('assert')
const crypto = require('crypto')
const ec_pem = require('../ec_pem')

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
    const alice = crypto.createECDH('secp521r1')
    alice.generateKeys()

    const bob = ec_pem.loadPrivateKey(keys.priv)
    const bob_secret = bob.computeSecret(alice.getPublicKey('hex'), 'hex', 'hex')

    const bob_key = ec_pem.loadPublicKey(keys.pub, 'hex')
    const alice_secret = alice.computeSecret(bob_key.public_key, 'hex', 'hex')

    //console.log({equal: bob_secret == alice_secret, bob_secret, alice_secret})
    assert.equal(bob_secret, alice_secret)

    assert.equal(bob_key.public_key, bob.getPublicKey('hex'))
  })
})

