"use strict"
const assert = require('assert')
const crypto = require('crypto')
const ec_pem = require('../ec_pem')

const algList = 'ecdsa-with-SHA1 sha1 sha224 sha256 sha512'.split(/\s+/)
const curveList = 'prime192v1 prime256v1 sect163k1 sect163r2 secp224r1 sect233k1 sect233r1 sect283k1 sect283r1 secp384r1 sect409k1 sect409r1 secp521r1 sect571k1 sect571r1'.split(/\s+/)

describe('test signature matrix native', () => {
  const sampleData = {
    data0: new Buffer('hello'),
    data1: crypto.randomBytes(4096),
    data2: crypto.randomBytes(65536), }

  for (let curve of curveList)
    for (let alg of algList)
      for (let dataKey of Object.keys(sampleData))
        it(`using curve: "${curve}" alg: "${alg}" and sample "${dataKey}"`, () =>
          assert(testSignatureRoundTrip(curve, alg, sampleData[dataKey]), {curve, alg}) )

  function testSignatureRoundTrip(curve, alg, data) {
    const key = ec_pem.generate(curve)

    const sign = crypto.createSign(alg)
    sign.update(data)
    const signature = sign.sign(key.encodePrivateKey())

    const verify = crypto.createVerify(alg)
    verify.update(data)
    const valid = verify.verify(key.encodePublicKey(), signature)

    //console.log(valid, {curve, alg}, {len_data: data.length, len_signature: signature.length})
    return valid
  }
})

describe('test signature matrix api', () => {
  const sampleData = {
    data0: new Buffer('hello'),
    //data1: crypto.randomBytes(4096),
    //data2: crypto.randomBytes(65536),
  }

  for (let curve of curveList)
    for (let alg of algList)
      for (let dataKey of Object.keys(sampleData))
        it(`using curve: "${curve}" alg: "${alg}" and sample "${dataKey}"`, () =>
          assert(testSignatureRoundTrip(curve, alg, sampleData[dataKey]), {curve, alg}) )

  function testSignatureRoundTrip(curve, alg, data) {
    const key = ec_pem.generate(curve)
    const signature = key.sign(alg, data).sign()
    const valid = key.verify(alg, data).verify(signature)
    return valid
  }
})
