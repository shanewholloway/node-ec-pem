'use strict'
const fs = require('fs')
const {isIP} = require('net')
const tmp = require('tmp')
const child_process = require('child_process')

const ec_pem = require('./ec_pem')

function _unpackSigningArgs(options, ec) {
  if (ec !== undefined)
    return [options || {}, ec]
  if ('function' === typeof options.generateKeys)
    return [{}, ec=options]
  if (ec == null)
    ec = options.ec || ec_pem.generate('prime256v1')

  return [options || {}, ec] }

function asCertRequestArgs(subjects, options, ec) {
  [options, ec] = _unpackSigningArgs(options, ec)
  if (subjects)
    options.subjects = subjects

  if (!options.altNames)
    options.altNames = [subjects]
  if (!options.config)
    options.config = configForOpenSSLRequest(options)
  return [options, ec] }


function configForOpenSSLRequest(opt) {
  let subjects = opt.subjects
  if ('string' === typeof subjects)
    subjects = [`CN = ${subjects}`]

  else if (!subjects.forEach)
    subjects = Object.keys(subjects)
      .map(k => `${k} = ${subjects[k]}`)

  return `\
[req]
req_extensions = v3_req
distinguished_name = req_subjects
prompt = no

[ req_subjects ]
${subjects.join('\n')}

${extensionConfigForOpenSSL(opt, 'v3_req')} `}


function extensionConfigForOpenSSL(opt, req_extensions='v3_req') {
  // c.f. https://www.openssl.org/docs/man1.0.1/apps/x509v3_config.html
  // c.f. http://wiki.cacert.org/FAQ/subjectAltName
  // c.f. http://apetec.com/support/generatesan-csr.htm

  if (!opt.keyUsage)
    opt.keyUsage = 'digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign'

  let extendedKeyUsage = opt.extendedKeyUsage
    && opt.extendedKeyUsage.join ? opt.extendedKeyUsage.join(', ') : opt.extendedKeyUsage
  extendedKeyUsage = !extendedKeyUsage ? ''
    : `extendedKeyUsage = ${extendedKeyUsage.join ? extendedKeyUsage.join(', ') : extendedKeyUsage}`

  let altNameSource = opt.altNames || []
  if ('string' === typeof altNameSource)
    altNameSource = altNameSource.split(/\s+/)

  let altNames=[], idx_ip=0, idx_dns=0
  for (let n of altNameSource)
    if (isIP(n))
      altNames.push(`IP.${++idx_ip} = ${n}`)
    else
      altNames.push(`DNS.${++idx_dns} = ${n}`)

  if (altNames.length)
    altNames = ['subjectAltName = @san_list', '', '[san_list]'].concat(altNames)

  return `\
[ ${req_extensions} ]
basicConstraints = CA:${opt.CA ? 'TRUE' : 'FALSE'}
keyUsage = ${opt.keyUsage.join ? opt.keyUsage.join(', ') : opt.keyUsage}
subjectKeyIdentifier = hash
${extendedKeyUsage}

${altNames.join('\n')}` }



function generateCertificateSigningRequest(subjects, options, ec) {
  [options, ec] = asCertRequestArgs(subjects, options, ec)
  return openssl_req(options, ec)
    .then(csr => Object.defineProperties({csr}, {ec: {value: ec}}) )}

function createSignedCertificate(csr, ca_key, ca_cert, options) {
  if (!options) options = {}
  if (csr == null)
    throw new Error("Parameter 'csr' is required. (e.g. csr = generateCertificateSigningRequest('example.com', ec))")
  if (ca_key == null)
    throw new Error("Parameter 'ca_key' is required. (e.g. ca_key = ec_pem.generate('prime256v1'))")
  else if ('function' !== typeof ca_key.generateKeys)
    ca_key = ec_pem.load(ca_key)
  if (ca_cert == null)
    throw new Error("Parameter 'ca_cert' is required. (e.g. ca_cert = createSelfSignedCertificate('example.com', ca_key))")

  return Promise.all([csr, ca_key, ca_cert, options])
    .then(([csr, ca_key, ca_cert, options]) =>
      openssl_x509(csr, ca_key, ca_cert, options)
        .then(cert => {
          const ec = csr.ec
          const cert_chain = [cert].concat(ca_cert.cert_chain || ca_cert.cert || ca_cert)
          cert = cert_chain.join('')
          csr = csr.csr || csr

          let ans = {cert, cert_chain, ca: ca_cert, csr: csr}
          if (ec) Object.defineProperties(ans, {ec: {value: ec}})
          return ans }))}

function createSelfSignedCertificate(subjects, options, ec) {
  [options, ec] = asCertRequestArgs(subjects, options, ec)
  options.self_sign = true
  return openssl_req(options, ec)
    .then(cert => asTLSOptions(cert, ec)) }

function asTLSOptions(cert, ec) {
  return Promise.resolve(cert).then(cert => {
    if (ec == null)
      ec = cert.ec
    if (ec == null)
      throw new Error("Parameter 'ec' is required and should be used to create cert")

    return Object.defineProperties(
      {cert: cert.cert || cert, key: ec_pem.encodePrivateKey(ec)},
      {ec: {value: ec}}) })}


const example_subjects = {
  CN: 'example.com', // common name (required)
  C: 'us', // country
  ST: 'colorado', // state
  L: 'colorado', // location
  O: 'example org', // organization
  OU: 'example org unit', // organizational unit
}

// openssl req -new -key «ec private key» [-x509] -subj "/CN=example.com"
function openssl_req(options, ec) {
  if ('string' === typeof options)
    options = {self_sign: true, subjects: {CN: options}}

  return Promise.all([
      tmpfile(options.config),
      tmpfile(ec_pem.encodePrivateKey(ec)) ])
    .then(tmpList => {
      const [tmp_config, tmp_key] = tmpList
      let args = ['req', '-new', '-sha256', '-key', tmp_key.path]


      if (tmp_config)
        args.push('-config', tmp_config.path)

      if (options.self_sign) {
        args.push('-x509', '-extensions', 'v3_req', '-days', options.days || 1)
      }

      args = args.filter(e => e)
      return openssl_cmd(args)
        .then(resp => {
          tmpList.forEach(e => e && e.cleanup())
          return resp.stdout }) })}


// openssl x509 -req -in «/tmp/.../csr.pem» -CAkey «ec private key»
function openssl_x509(csr, ca_key, ca_cert, options) {
  if (!options) options = {}
  if (!ca_cert)
    throw new Error("Parameter 'ca_cert' is required")

  if (!options.extensions)
    options.extensions = extensionConfigForOpenSSL(options, 'v3_req')

  return Promise.all([
      tmpfile(csr.csr || csr),
      tmpfile(ca_cert.cert || ca_cert),
      tmpfile(options.extensions),
      tmpfile(ec_pem.encodePrivateKey(ca_key)) ])
    .then(tmpList => {
      const [tmp_csr, tmp_ca_cert, tmp_ext, tmp_ca_key] = tmpList

      let args = ['x509', '-req', '-sha256']
      args.push('-days', options.days || 1, '-set_serial', options.serial || '00')
      args.push('-extensions', 'v3_req', '-extfile', tmp_ext.path)
      args.push('-in', tmp_csr.path, '-CA', tmp_ca_cert.path, '-CAkey', tmp_ca_key.path)

      return openssl_cmd(args)
        .then(resp => {
          tmpList.forEach(e => e && e.cleanup())
          return resp.stdout }) })}


openssl_inspect.presets = {
  req: ['req', '-noout', '-text'],
  x509: ['x509', '-noout', '-text'],
  verify: ['verify', '-verbose'], }

function openssl_inspect(args, input) {
  if ('string' === typeof args)
    args = openssl_inspect.presets[args] || [args]

  return Promise.all([Promise.all(args), Promise.resolve(input)])
    .then(([args, input]) => openssl_cmd(args, {input}))
    .then(resp => { return resp.stdout }) }


let _openssl_queue = Promise.resolve()
function openssl_cmd(args, options) {
  const tip = _openssl_queue.then(() =>
    spawn_cmd('openssl', args, options))
  _openssl_queue = tip
  return tip }


// child_process.spawn with {stdout, stderr}, Promises
function spawn_cmd(command, args, options) {
  if (!options) options = {}

  return new Promise((resolve, reject) => {
    let io = {stdout: [], stderr: []}
    let finish = () =>
      ({stdout: io.stdout.join(''), stderr: io.stderr.join('')})

    let child = child_process.spawn(command, args,
      Object.assign({stdio:'pipe'}, options))

    if (options.input) {
      child.stdin.write(options.input)
      child.stdin.end()
    } else if (options.stdin)
      options.stdin.pipe(child.stdin)

    child.on('error', err => reject({err, __proto__: finish()}) )
    child.on('close', exitCode => exitCode
       ? reject({exitCode, __proto__: finish()})
       : resolve(finish()))

    child.stdout.on('data', data => io.stdout.push(data) )
    child.stderr.on('data', data => io.stderr.push(data) )
    return child })}


const _fs_write = (...args) =>
  new Promise((resolve, reject) =>
    fs.write(...args,
      (err, ans) => err ? reject(err) : resolve(ans)) )
const _fs_close = (...args) =>
  new Promise((resolve, reject) =>
    fs.close(...args,
      (err, ans) => err ? reject(err) : resolve(ans)) )

const tmpfile = (content) =>
  Promise.resolve(content).then(content => {
    if (!content) return;
    return _tmpfile(content)
      .catch(() => _tmpfile(content))
      .catch(() => _tmpfile(content))
  })

const _tmpfile = (content) =>
  new Promise((resolve, reject) =>
    tmp.file((err, path, fd, cleanup) => {
      if (err) return reject(err)
      _fs_write(fd, content)
        .catch(err => (_fs_close(fd), reject(err)))
        .then(() => _fs_close(fd))
        .then(() => resolve({path, cleanup}), reject) }))



Object.assign(exports, {
  generateCertificateSigningRequest, generateCSR: generateCertificateSigningRequest,
  createSignedCertificate, createSelfSignedCertificate, selfCert: createSelfSignedCertificate,
  asTLSOptions,
  asCertRequestArgs, configForOpenSSLRequest,

  openssl_req, openssl_x509, openssl_cmd, openssl_inspect,
  spawn_cmd,
})

