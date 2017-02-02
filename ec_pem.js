'use strict'
const crypto = require('crypto')
const asn1 = require('asn1.js')

const ec_pem_api = {
    encodePrivateKey(enc) { return encodePrivateKey(this, enc) },
    encodePublicKey(enc) { return encodePublicKey(this, enc) },
    sign(algorithm, ...optionalArgs) { return sign(this, algorithm, ...optionalArgs) },
    verify(algorithm, ...optionalArgs) { return verify(this, algorithm, ...optionalArgs) },
    clone(kind) { return clone(this, kind) },
    toJSON(kind) { return toJSON(this, kind) },
    toBase64(kind) { return toBase64(this, kind) },
}

const curveByKeySize = {
  '49': [ 'prime192v1' ],
  '49,24': [ 'prime192v1' ],
  '65': [ 'prime256v1' ],
  '65,32': [ 'prime256v1' ],
  '43': [ 'sect163k1', 'sect163r2' ],
  '43,21': [ 'sect163k1', 'sect163r2' ],
  '43,20': [ 'sect163k1', 'sect163r2' ],
  '57': [ 'secp224r1' ],
  '57,28': [ 'secp224r1' ],
  '61': [ 'sect233k1', 'sect233r1' ],
  '61,29': [ 'sect233k1', 'sect233r1' ],
  '61,28': [ 'sect233r1' ],
  '73': [ 'sect283k1', 'sect283r1' ],
  '73,36': [ 'sect283k1', 'sect283r1' ],
  '73,35': [ 'sect283k1', 'sect283r1' ],
  '97': [ 'secp384r1' ],
  '97,48': [ 'secp384r1' ],
  '105': [ 'sect409k1', 'sect409r1' ],
  '105,51': [ 'sect409k1', 'sect409r1' ],
  '133': [ 'secp521r1' ],
  '133,66': [ 'secp521r1' ],
  '133,65': [ 'secp521r1' ],
  '145': [ 'sect571k1', 'sect571r1' ],
  '145,71': [ 'sect571k1', 'sect571r1' ],
  '145,72': [ 'sect571k1', 'sect571r1' ] }

function ec_pem(ecdh, curve) {
  if ('string' === typeof ecdh && undefined === curve)
    curve = ecdh, ecdh = null;
  else if (!curve && ecdh)
    curve = ecdh.curve || inferCurve(ecdh, true)

  if (!curve)
    throw new Error("EC curve must be specified for PEM encoding support")

  if (null == ecdh)
    ecdh = crypto.createECDH(curve)
  return Object.assign(ecdh, ec_pem_api, {curve})
}

exports = module.exports = Object.assign(ec_pem, {
  ec_pem, ec_pem_api, generate, load, decode, sign, verify,
  loadPrivateKey, decodePrivateKey, encodePrivateKey,
  loadPublicKey, decodePublicKey, encodePublicKey,
  clone, toJSON, fromJSON, toBase64, fromBase64, asUrlSafeBase64,
  inferCurve, inferCurveByLengths,
  pemDecodeRaw, pemEncodeRaw })


function inferCurve(ecdh, exactlyOne) {
  const keyLengths = [ecdh.getPublicKey().length, ecdh.getPrivateKey().length]
  return inferCurveByLengths(keyLengths, exactlyOne) }
function inferCurveByLengths(keyLengths, exactlyOne) {
  if (Number.isInteger(keyLengths))
    keyLengths = [keyLengths,]
  const ans = curveByKeySize[keyLengths]
  if (!exactlyOne) return ans
  return (ans.length === 1) ? ans[1] : null }


function generate(curve) {
  const ecdh = crypto.createECDH(curve)
  ecdh.generateKeys()
  return ec_pem(ecdh, curve)
}

function clone(ecdh, kind) {
  let copy = ec_pem(null, ecdh.curve)
  switch (kind) {
  case 'private':
    copy.setPrivateKey(ecdh.getPrivateKey())
    return copy

  case 'public': case false:
    copy.setPublicKey(ecdh.getPublicKey())
    return copy

  case true: case null: case undefined:
    try { copy.setPrivateKey(ecdh.getPrivateKey()) }
    catch (err) { copy.setPublicKey(ecdh.getPublicKey()) }
    return copy

  default: throw new Error('Invalid kind for ec-pem::clone')
  }
}

function asUrlSafeBase64(sz) {
  // See [modified Base64 for URL](https://en.wikipedia.org/wiki/Base64#URL_applications)
  //  > …where the '+' and '/' characters of standard Base64 are respectively replaced by '-' and '_' … omitting the padding '='
  // Note: Buffer.from(sz, 'base64') correctly interprets this variant. String::toString('base64') just cannot produce it, unfortunately.
  if (sz && Buffer.isBuffer(sz)) sz = sz.toString('base64')
  return sz.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'')
}

function toJSON(ecdh, kind) {
  let obj = {curve: ecdh.curve}
  switch (kind) {
  case 'private':
    obj.private_key = asUrlSafeBase64(ecdh.getPrivateKey('base64'))
    return obj

  case 'public': case false:
    obj.public_key = asUrlSafeBase64(ecdh.getPublicKey('base64'))
    return obj

  case true: case null: case undefined: default:
    try { obj.private_key = asUrlSafeBase64(ecdh.getPrivateKey('base64')) }
    catch (err) { obj.public_key = asUrlSafeBase64(ecdh.getPublicKey('base64')) }
    return obj
  }
}
function fromJSON(obj) {
  let ecdh = ec_pem(null, obj.curve)
  if (obj.private_key)
    ecdh.setPrivateKey(obj.private_key, 'base64')
  else if (obj.public_key)
    ecdh.setPublicKey(obj.public_key, 'base64')
  return ecdh
}

const rx_base64_encoded = /[A-Za-z0-9.+/=_-]/
function toBase64(ecdh, kind) {
  let hdr = {curve: ecdh.curve}
  let b64_ec_key

  switch (kind) {
  case 'private':
    b64_ec_key = asUrlSafeBase64(ecdh.getPrivateKey('base64'))
    hdr.kind = 'private'
    break

  case 'public': case false:
    b64_ec_key = asUrlSafeBase64(ecdh.getPublicKey('base64'))
    hdr.kind = 'public'
    break

  case true: case null: case undefined: default:
    try {
      b64_ec_key = asUrlSafeBase64(ecdh.getPrivateKey('base64'))
      hdr.kind = 'private'
    } catch (err) {
      b64_ec_key = asUrlSafeBase64(ecdh.getPublicKey('base64'))
      hdr.kind = 'public'
    }
    break
  }
  const b64_hdr = asUrlSafeBase64(Buffer(JSON.stringify(hdr)).toString('base64'))
  return `${b64_hdr}.${b64_ec_key}`
}
function fromBase64(content) {
  const parts = content.split('.')
    .map(part => Buffer.from(part, 'base64'))
  const hdr = JSON.parse(parts[0].toString())

  let ecdh = ec_pem(null, hdr.curve)
  if ('public' === hdr.kind)
    ecdh.setPublicKey(parts[1])
  else if ('private' === hdr.kind)
    ecdh.setPrivateKey(parts[1])
  return ecdh
}

function load(content) {
  if (content.curve)
    return fromJSON(content)
  if (rx_pem_ec_private_key.test(content))
    return loadPrivateKey(content)
  if (rx_pem_public_key.test(content))
    return loadPublicKey(content)
  if (rx_base64_encoded.test(content))
    return fromBase64(content)
  throw new Error("Not a valid PEM formatted EC key")
}
function decode(pem_key_string) {
  if (rx_pem_ec_private_key.test(pem_key_string))
    return decodePrivateKey(pem_key_string)
  if (rx_pem_public_key.test(pem_key_string))
    return decodePublicKey(pem_key_string)
  throw new Error("Not a valid PEM formatted EC key")
}

function loadPrivateKey(content) {
  if (content.curve) {
    let ecdh = ec_pem(null, content.curve)
    ecdh.setPrivateKey(content.private_key)
    return ecdh
  } else if (!rx_pem_ec_private_key.test(content))
    throw new Error("Not a valid PEM formatted EC private key")

  const key = decodePrivateKey(content)
  const ecdh = ec_pem(null, key.curve)
  ecdh.setPrivateKey(key.private_key)
  return ecdh
}

const rx_pem_generic = /-----BEGIN ([^-\r\n]+)-----\n([^-]*)-----END \1-----/
function pemDecodeRaw(pem_key_string) {
  const pem_match = rx_pem_generic.exec(pem_key_string)
  if (!pem_match) throw new Error("Invalid PEM text embedding")

  return {heading: pem_match[1], content: Buffer.from(pem_match[2], 'base64')}
}

function pemEncodeRaw(heading, content) {
  let lines = Buffer.from(content).toString('base64').split(/.{64}/)
  lines.unshift(`-----BEGIN ${heading}-----`)
  lines.push(`-----END ${heading}-----`)
  return lines.join('\n')
}

const rx_pem_ec_private_key = /-----BEGIN EC PRIVATE KEY-----\n([^-]*)-----END EC PRIVATE KEY-----/
function decodePrivateKey(pem_key_string) {
  const pem_match = rx_pem_ec_private_key.exec(pem_key_string)
  if (pem_match) pem_key_string = Buffer.from(pem_match[1], 'base64')

  var obj = ASN1_ECPrivateKey.decode(pem_key_string)

  const curve_key = obj.ec_params.value.join('.')
  const curve = asn1_objid_lookup_table[curve_key]
  obj.curve = curve ? curve.name : curve_key

  return obj
}

const _encode_private_key_extra = {
  pem: {label: 'EC PRIVATE KEY'}}
function encodePrivateKey(ecdh, enc='pem') {
  let curve = ecdh.curve || inferCurve(ecdh, true)
  if (!curve)
    throw new Error('Missing required attribute "ecdh.curve"; (e.g. ecdh.curve = \'prime256v1\')')

  const asn1_curve = asn1_objid_lookup_table[curve]

  var obj = {version: 1,
    private_key: ecdh.getPrivateKey(),
    ec_params: { type: 'curve', value: asn1_curve.value},
    public_key: {unused: 0, data: ecdh.getPublicKey()}}

  return ASN1_ECPrivateKey.encode(obj, enc, _encode_private_key_extra[enc])+'\n'
}



function loadPublicKey(content, encoding) {
  if (content.public_key && content.curve) {
    const ecdh = ec_pem(null, content.curve)
    ecdh.setPublicKey(content.public_key)
    return ecdh
  } else if (!rx_pem_public_key.test(content))
    throw new Error("Not a valid PEM formatted EC public key")

  const key = decodePublicKey(content)
  if (null != encoding) {
    var public_key = key.public_key.data.toString(encoding)
    return {curve: key.curve, public_key}
  }

  const ecdh = ec_pem(null, key.curve)
  ecdh.setPublicKey(key.public_key.data)
  return ecdh
}

const rx_pem_public_key = /-----BEGIN PUBLIC KEY-----\n([^-]*)-----END PUBLIC KEY-----/
function decodePublicKey(pem_key_string) {
  const pem_match = rx_pem_public_key.exec(pem_key_string)
  if (pem_match) pem_key_string = Buffer.from(pem_match[1], 'base64')

  var obj = ASN1_ECPublicKey.decode(pem_key_string)

  const alg_key = obj.algorithm.algorithm.join('.')
  const alg = asn1_objid_lookup_table[alg_key]
  obj.alg = alg ? alg.name : alg_key

  const curve_key = obj.algorithm.curve.join('.')
  const curve = asn1_objid_lookup_table[curve_key]
  obj.curve = curve ? curve.name : curve_key

  return obj
}

const _encode_public_key_extra = {
  pem: {label: 'PUBLIC KEY'}}
function encodePublicKey(ecdh, enc='pem') {
  const alg = asn1_objid_lookup_table['id-ecPublicKey']
  const curve = asn1_objid_lookup_table[ecdh.curve]
  const public_key = ecdh.public_key || ecdh.getPublicKey()

  var obj = {
    algorithm: { algorithm: alg.value, curve: curve.value },
    public_key: {unused: 0, data: public_key}}

  return ASN1_ECPublicKey.encode(obj, enc, _encode_public_key_extra[enc])+'\n'
}


function sign(ecdh, algorithm, ...args) {
  let sign = crypto.createSign(algorithm)
  let _do_sign = sign.sign
  sign.sign = signature_format =>
    _do_sign.call(sign, encodePrivateKey(ecdh, 'pem'), signature_format)
  return args ? sign.update(...args) : sign }

function verify(ecdh, algorithm, ...args) {
  let verify = crypto.createVerify(algorithm)
  let _do_verify = verify.verify
  verify.verify = (signature, signature_format) =>
    _do_verify.call(verify, encodePublicKey(ecdh, 'pem'), signature, signature_format)
  return args ? verify.update(...args) : verify }



// ASN1 definitions for Elliptic Curve PKI structures.
//
// References:
//
// - [RFC 5915](https://tools.ietf.org/html/rfc5915): Elliptic Curve Private Key Structure
// - [RFC 5480](https://tools.ietf.org/html/rfc5480): Elliptic Curve Cryptography Subject Public Key Information
//

const ASN1_ECPrivateKey = asn1.define('ECPrivateKey', function(){
  this.seq().obj(
    this.key('version').int(),
    this.key('private_key').octstr(),
    this.key('ec_params').optional().explicit(0).use(ASN1_ECParams),
    this.key('public_key').optional().explicit(1).bitstr()) })

const ASN1_ECParams = asn1.define('ECParams', function(){
  this.choice({curve: this.objid()}) })

const ASN1_ECPublicKey = asn1.define('ECPublicKey', function(){
  this.seq().obj(
    this.key('algorithm').use(ASN1_ECAlgorithm),
    this.key('public_key').bitstr()) })

const ASN1_ECAlgorithm = asn1.define('ECAlgorithm', function(){
  this.seq().obj(
    this.key('algorithm').objid(),
    this.key('curve').objid().optional(),
    this.key('ec_params').seq().obj(
      this.key('p').int(),
      this.key('q').int(),
      this.key('g').int()
    ).optional()) })



// From [RFC 5480 Section-2.1.1](https://tools.ietf.org/html/rfc5480#section-2.1.1)

const asn1_objid_lookup_table = new (function () {
    const add = (name, value) => {
      let key = value.join('.')
      this[name] = this[key] = {name, value, key}
      return this }

    add('id-ecPublicKey', [1, 2, 840, 10045, 2, 1])
    add('id-ecDH', [1, 3, 132, 1, 12])
    add('id-ecMQV', [1, 3, 132, 1, 13])

    add('prime192v1', [1, 2, 840, 10045, 3, 1, 1])
    add('prime256v1', [1, 2, 840, 10045, 3, 1, 7])

    add('sect163k1', [1, 3, 132, 0, 1])
    add('sect163r2', [1, 3, 132, 0, 15])
    add('secp224r1', [1, 3, 132, 0, 33])
    add('sect233k1', [1, 3, 132, 0, 26])
    add('sect233r1', [1, 3, 132, 0, 27])
    add('sect283k1', [1, 3, 132, 0, 16])
    add('sect283r1', [1, 3, 132, 0, 17])
    add('secp384r1', [1, 3, 132, 0, 34])
    add('sect409k1', [1, 3, 132, 0, 36])
    add('sect409r1', [1, 3, 132, 0, 37])
    add('secp521r1', [1, 3, 132, 0, 35])
    add('sect571k1', [1, 3, 132, 0, 38])
    add('sect571r1', [1, 3, 132, 0, 39])

    return this
})

