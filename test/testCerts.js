'use strict'
const assert = require('assert')
const fs = require('fs')
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
  csr: [ '-----BEGIN CERTIFICATE REQUEST-----',
         'MIIB0DCCATICAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wgZswEAYHKoZIzj0C',
         'AQYFK4EEACMDgYYABAGcWMZFIio39qpUZeR0CivdeQeR1vNDrGnB49rT71280vMJ',
         'RSvHr2uG7Z4/hqaHKOyEQrdSslqaNqtQZugJoxi6pgEch+G7mxKL5R6fxK9GskGH',
         'afMceUSIGxFYnUL+k3GmelMR/Imv7XmdYX3c4KXiEtkln5btXaeYU/Et2jiI+vis',
         'nqB3MHUGCSqGSIb3DQEJDjFoMGYwCQYDVR0TBAIwADALBgNVHQ8EBAMCAf4wHQYD',
         'VR0OBBYEFFPasyZgab6ZlbigEtvCJChVh613MC0GA1UdEQQmMCSCC2V4YW1wbGUu',
         'Y29tgg93d3cuZXhhbXBsZS5jb22HBAHqOP8wCQYHKoZIzj0EAQOBjAAwgYgCQgF3',
         'GsmvJCguKDh+tCPHIURmwY3oNRTHp45hQmDXLHXCoWyLLhctAFeJ1cLE67ZRgQma',
         'XCeOsLpy26yuex5bUg5QDQJCAJSYxRxmCRSvuMdRJngUx+t7cLyxIIl/0yM0BqUF',
         'ACBO698KqfZK+B4y6qthqfmphfL6UPTq66FpfZ6sSL37wsmb',
         '-----END CERTIFICATE REQUEST-----',
         '' ],
  cert:[ '-----BEGIN CERTIFICATE-----',
         'MIICETCCAXOgAwIBAgIJAMFhnjz64+y8MAkGByqGSM49BAEwFjEUMBIGA1UEAwwL',
         'ZXhhbXBsZS5jb20wHhcNMTcwMTA2MDEyMzQ2WhcNMTcwMTA3MDEyMzQ2WjAWMRQw',
         'EgYDVQQDDAtleGFtcGxlLmNvbTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAZxY',
         'xkUiKjf2qlRl5HQKK915B5HW80OsacHj2tPvXbzS8wlFK8eva4btnj+Gpoco7IRC',
         't1KyWpo2q1Bm6AmjGLqmARyH4bubEovlHp/Er0ayQYdp8xx5RIgbEVidQv6TcaZ6',
         'UxH8ia/teZ1hfdzgpeIS2SWflu1dp5hT8S3aOIj6+Kyeo2gwZjAJBgNVHRMEAjAA',
         'MAsGA1UdDwQEAwIB/jAdBgNVHQ4EFgQUU9qzJmBpvpmVuKAS28IkKFWHrXcwLQYD',
         'VR0RBCYwJIILZXhhbXBsZS5jb22CD3d3dy5leGFtcGxlLmNvbYcEAeo4/zAJBgcq',
         'hkjOPQQBA4GMADCBiAJCAIu2gPBnmx9bx5J18o0UzoHWvl8HrVFpcMPDqscYx7RY',
         'Rmjg9IMdG98g6La8LfFZsziAD1lsRLw8UmS+L70znOFQAkIAqvJYQS8OH1HabreV',
         'G7IYuT5jNrdHiz8kTQhAwYRjMFHGiQmxN38FmFLXkOXFZv1Vqpv7dJy4IyVhHkd1',
         'rou3bP8=',
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
    ec_cert.generateCSR('example.com',
        {ec, altNames: ['example.com', 'www.example.com', '1.234.56.255']})
      .then(options => {
        let csr = options.csr.split(/\r?\n/m)
        let test = csr.map((l, i) => l == test_data.csr[i] ? '1' : '0').join('')
        assert((test == '1011111000011') || (test == '1111111000011'), test)
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
    ec_cert.createSelfSignedCertificate('example.com',
        {ec, altNames: ['example.com', 'www.example.com', '1.234.56.255']})
      .then(options => {
        let cert = options.cert.split(/\r?\n/m)
        let test = cert.map((l, i) => l == test_data.cert[i] ? '1' : '0').join('')
        assert((test == '100111111000011') || (test == ''), test)
      }).then(() => done(), done)
  })
})

describe('test using EC self-signed certificate', () => {
  let ec, cert_options, ca_list

  before(() => {
    ec = ec_pem.generate('prime256v1')
    cert_options = ec_cert.createSelfSignedCertificate('localhost',
      {ec, altNames: ['localhost', '127.0.0.1']})
    ca_list = [cert_options.then(options => options.cert)]
  })

  it('with tls over localhost', done => do_tls_server_test('localhost', cert_options, ca_list, done))
  it('with tls over 127.0.0.1', done => do_tls_server_test('127.0.0.1', cert_options, ca_list, done))
  it('with https over localhost', done => do_https_server_test('localhost', cert_options, ca_list, done))
  it('with https over 127.0.0.1', done => do_https_server_test('127.0.0.1', cert_options, ca_list, done))
})

describe('test EC signing a CSR', () => {
  let ec, csr
  before(() => {
    ec = ec_pem.generate('prime256v1')
    csr = ec_cert.generateCSR('example.com', ec)
  })

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
  const altNames = ['localhost', '127.0.0.1']
  let ec, csr, ec_ca, ec_ca_cert, cert, cert_options
  before(() => {
    ec = ec_pem.generate('prime256v1')
    csr = ec_cert.generateCSR('localhost',
      {ec, altNames})

    ec_ca = ec_pem.loadPrivateKey(test_data.priv)
    ec_ca_cert = test_data.cert.join('\n')
    cert = ec_cert.createSignedCertificate(csr, ec_ca, ec_ca_cert,
      {altNames})

    cert_options = ec_cert.asTLSOptions(cert, ec)
  })

  it('with tls over localhost', done => do_tls_server_test('localhost', cert_options, [ec_ca_cert], done))
  it('with tls over 127.0.0.1', done => do_tls_server_test('127.0.0.1', cert_options, [ec_ca_cert], done))
  it('with https over localhost', done => do_https_server_test('localhost', cert_options, [ec_ca_cert], done))
  it('with https over 127.0.0.1', done => do_https_server_test('127.0.0.1', cert_options, [ec_ca_cert], done))
})

function do_tls_server_test(resolveName, cert_options, ca_list, done) {
  assert(ca_list.length > 0)
  cert_options
    .then(options => tls.createServer(options) )
    .then(svr => {
      svr.on('secureConnection', sock => done())
      svr.on('error', err => done(err))
      svr.listen(0, resolveName, () => {
        Promise.all(ca_list).then(ca => {
          let sock = tls.connect(svr.address().port,
            {requestCert:true, rejectUnauthorized: true, ca},
            () => {
              let pc = sock.getPeerCertificate(true)
              //console.log({pc})
            })})
      }) })
    .catch(done) }

function do_https_server_test(resolveName, cert_options, ca_list, done) {
  assert(ca_list.length > 0)
  cert_options
    .then(options => https.createServer(options) )
    .then(svr => {
      svr.on('request', (req,res) => {
        res.writeHead(211)
        res.end('hello world\n')
      })
      svr.on('error', err => done(err))
      svr.listen(0, resolveName, () => {
        Promise.all(ca_list).then(ca =>
          https.get({hostname: resolveName, port:svr.address().port, pathname:'/', rejectUnauthorized: true, ca},
            res => { done(res.statusCode = 211 ? null : new Error(`Wrong status code: ${res.statusCode}`)) }))
      }) })
    .catch(done) }


