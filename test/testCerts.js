'use strict'
const assert = require('assert')
const tls = require('tls')
const https = require('https')
const crypto = require('crypto')
const ec_pem = require('../ec_pem')
const ec_cert = require('../cert')

const debug = !!process.env.debug

const test_data = {
  priv: ['-----BEGIN EC PRIVATE KEY-----',
         'MIHbAgEBBEGBGI8CO/hGZWi0fW1RZbitCb+eyxZfhIA3bwmm6o1LltiIcRguGcpR',
         'nSJqfDjKAFFNZ+yBpQzZl2eVItKnX7z5RKAHBgUrgQQAI6GBiQOBhgAEAZxYxkUi',
         'Kjf2qlRl5HQKK915B5HW80OsacHj2tPvXbzS8wlFK8eva4btnj+Gpoco7IRCt1Ky',
         'Wpo2q1Bm6AmjGLqmARyH4bubEovlHp/Er0ayQYdp8xx5RIgbEVidQv6TcaZ6UxH8',
         'ia/teZ1hfdzgpeIS2SWflu1dp5hT8S3aOIj6+Kye',
         '-----END EC PRIVATE KEY-----',
         ''].join('\n'),
  csr:  ['-----BEGIN CERTIFICATE REQUEST-----',
         'MIIBWDCBuwIBADAWMRQwEgYDVQQDEwtleGFtcGxlLmNvbTCBmzAQBgcqhkjOPQIB',
         'BgUrgQQAIwOBhgAEAZxYxkUiKjf2qlRl5HQKK915B5HW80OsacHj2tPvXbzS8wlF',
         'K8eva4btnj+Gpoco7IRCt1KyWpo2q1Bm6AmjGLqmARyH4bubEovlHp/Er0ayQYdp',
         '8xx5RIgbEVidQv6TcaZ6UxH8ia/teZ1hfdzgpeIS2SWflu1dp5hT8S3aOIj6+Kye',
         'oAAwCQYHKoZIzj0EAQOBjAAwgYgCQgDHF5aP0qwi0DN6ynOqiIKxnCU/1FLg3ZKG',
         'kOzJX80l1rHjsQpKILX+cDq790aq2Wi8gxTPrNP/aqxCsT2zfcG0/wJCAMAtcL3C',
         'TiTlpoJZFcB63u/WX+Xe470V4h1mSfCiQT/Di1IOFE/POnxh97/qd1FugHTi6AUm',
         'qCzGR2S1qFpVJOLH',
         '-----END CERTIFICATE REQUEST-----',
         '' ],
  cert: ['-----BEGIN CERTIFICATE-----',
         'MIICHzCCAYKgAwIBAgIJAOKEYBZ9bJgIMAkGByqGSM49BAEwFjEUMBIGA1UEAxML',
         'ZXhhbXBsZS5jb20wHhcNMTYxMTIzMjAxODQ4WhcNMTYxMjIzMjAxODQ4WjAWMRQw',
         'EgYDVQQDEwtleGFtcGxlLmNvbTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAZxY',
         'xkUiKjf2qlRl5HQKK915B5HW80OsacHj2tPvXbzS8wlFK8eva4btnj+Gpoco7IRC',
         't1KyWpo2q1Bm6AmjGLqmARyH4bubEovlHp/Er0ayQYdp8xx5RIgbEVidQv6TcaZ6',
         'UxH8ia/teZ1hfdzgpeIS2SWflu1dp5hT8S3aOIj6+Kyeo3cwdTAdBgNVHQ4EFgQU',
         'U9qzJmBpvpmVuKAS28IkKFWHrXcwRgYDVR0jBD8wPYAUU9qzJmBpvpmVuKAS28Ik',
         'KFWHrXehGqQYMBYxFDASBgNVBAMTC2V4YW1wbGUuY29tggkA4oRgFn1smAgwDAYD',
         'VR0TBAUwAwEB/zAJBgcqhkjOPQQBA4GLADCBhwJBZcPVxyXbvLLgXZRrQvUAy45O',
         'ld2cVyqL/lh435HIY40RPDp1m2YU6a8ofDwoSGELhsgwgeFB6hvZ3U1x0IGqFNEC',
         'QgCqTeW7AZb1BEXwTuTYZqLukznggODtVpVE8L+cGNHcb2IpOgTlF79XkxbFID7A',
         '715fFDqtyKUSbwso3W1jVcf3Jw==',
         '-----END CERTIFICATE-----',
         '' ]
}


describe('test EC generating a CSR', () => {
  it('from a new ec_pem keypair', done => {
    const ec = ec_pem.generate('prime256v1')

    ec_cert.generateCSR('example.com', ec)
      .then(options => { assert(/BEGIN CERTIFICATE REQUEST/.test(options.csr), options.csr) })
      .then(() => done(), done)
  })

  it('from a new crypto.createECDH keypair', done => {
    const ec = crypto.createECDH('prime256v1')
    ec.curve = 'prime256v1'
    ec.generateKeys()

    ec_cert.generateCSR('example.com', ec)
      .then(options => { assert(/BEGIN CERTIFICATE REQUEST/.test(options.csr), options.csr) })
      .then(() => done(), done)
  })

  it('from a known EC Private Key in PEM format', done => {
    const ec = ec_pem.loadPrivateKey(test_data.priv)
    ec_cert.generateCSR('example.com', ec)
      .then(options => {
        let csr = options.csr.split(/\r?\n/m)
        let test = csr.map((l, i) => l == test_data.csr[i] ? '1' : '0').join('')
        assert((test == '11111000011') || (test == '10111000011'), test)
      }).then(() => done(), done)
  })
})


describe('test EC generating a self-signed certificate', () => {
  it('from a new ec_pem keypair', done => {
    const ec = ec_pem.generate('prime256v1')

    ec_cert.createSelfSignedCertificate('example.com', ec)
      .then(options => { assert(/BEGIN CERTIFICATE/.test(options.cert), options.cert) })
      .then(() => done(), done)
  })

  it('from a new crypto.createECDH keypair', done => {
    const ec = crypto.createECDH('prime256v1')
    ec.curve = 'prime256v1'
    ec.generateKeys()

    ec_cert.createSelfSignedCertificate('example.com', ec)
      .then(options => { assert(/BEGIN CERTIFICATE/.test(options.cert), options.cert) })
      .then(() => done(), done)
  })

  it('from a known EC Private Key in PEM format', done => {
    const ec = ec_pem.loadPrivateKey(test_data.priv)
    ec_cert.createSelfSignedCertificate('example.com', ec)
      .then(options => {
        let cert = options.cert.split(/\r?\n/m)
        let test = cert.map((l, i) => l == test_data.cert[i] ? '1' : '0').join('')
        assert((test == '100111110000011'), test)
      }).then(() => done(), done)
  })
})

describe('test using EC self-signed certificate', () => {
  const ec = ec_pem.generate('prime256v1')
  const cert_options = ec_cert.createSelfSignedCertificate('example.com', ec)

  it('with tls', done => do_tls_server_test(cert_options, done))
  it('with https', done => do_https_server_test(cert_options, done))
})

describe('test EC signing a CSR', () => {
  const ec = ec_pem.generate('prime256v1')
  const csr = ec_cert.generateCSR('example.com', ec)

  it('from a new ec_pem keypair', done => {
    const ec_ca = ec_pem.generate('prime256v1')
    const ec_ca_cert = ec_cert.createSelfSignedCertificate('example.com', ec_ca)

    ec_cert.createSignedCertificate(csr, ec_ca, ec_ca_cert)
      .then(()=>done(), done)
  })

  it('from a new crypto.createECDH keypair', done => {
    const ec_ca = crypto.createECDH('prime256v1')
    ec_ca.curve = 'prime256v1'
    ec_ca.generateKeys()
    const ec_ca_cert = ec_cert.createSelfSignedCertificate('example.com', ec_ca)

    ec_cert.createSignedCertificate(csr, ec_ca, ec_ca_cert)
      .then(()=>done(), done)
  })

  it('should work from a known EC Private Key in PEM format', done => {
    const ec_ca = ec_pem.loadPrivateKey(test_data.priv)
    const ec_ca_cert = test_data.cert.join('\n')

    ec_cert.createSignedCertificate(csr, ec_ca, ec_ca_cert)
      .then(()=>done(), done)
  })
})

describe('test using EC actual signed certificate', () => {
  const ec = ec_pem.generate('prime256v1')
  const csr = ec_cert.generateCSR('example.com', ec)

  const ec_ca = ec_pem.loadPrivateKey(test_data.priv)
  const ec_ca_cert = test_data.cert.join('\n')
  const cert = ec_cert.createSignedCertificate(csr, ec_ca, ec_ca_cert)

  const cert_options = ec_cert.asTLSOptions(cert, ec)

  it('with tls', done => do_tls_server_test(cert_options, done))
  it('with https', done => do_https_server_test(cert_options, done))
})

function do_tls_server_test(cert_options, done) {
  cert_options
    .then(options => tls.createServer(options) )
    .then(svr => {
      svr.on('secureConnection', sock => done())
      svr.on('error', err => done(err))
      svr.listen(0, '127.0.0.1', () => {
        tls.connect(svr.address().port,
          {rejectUnauthorized: false},
          ans => { })
      }) })
    .catch(done) }

function do_https_server_test(cert_options, done) {
  cert_options
    .then(options => https.createServer(options) )
    .then(svr => {
      svr.on('request', (req,res) => {
        res.writeHead(211)
        res.end('hello world\n')
      })
      svr.on('error', err => done(err))
      svr.listen(0, '127.0.0.1', () => {
        https.get(
          {hostname: '127.0.0.1', port:svr.address().port, pathname:'/', rejectUnauthorized: false},
          res => { done(res.statusCode = 211 ? null : new Error(`Wrong status code: ${res.statusCode}`)) })
      }) })
    .catch(done) }


