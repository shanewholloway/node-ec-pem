'use strict'
const fs = require('fs')
const tmp = require('tmp')
const child_process = require('child_process')

const ec_pem = require('./ec_pem')


function generateCertificateSigningRequest(subjects, ec) {
  if (ec == null)
    ec = ec_pem.generate('prime256v1')
  return openssl_req({subjects}, ec)
    .then(csr => 
      Object.defineProperties({csr},
        {ec: {value: ec}}) )}

function createSignedCertificate(csr, ca_key, ca_cert, options) {
  if (!options) options = {}
  if (csr == null)
    throw new Error("Parameter 'csr' is required. (e.g. csr = generateCertificateSigningRequest('example.com', ec))")
  if (ca_key == null)
    throw new Error("Parameter 'ca_key' is required. (e.g. ca_key = ec_pem.generate('prime256v1'))")
  if (ca_cert == null)
    throw new Error("Parameter 'ca_cert' is required. (e.g. ca_cert = createSelfSignedCertificate('example.com', ca_key))")

  return Promise.all([csr, ca_key, ca_cert, options])
    .then(args => openssl_x509(...args))
    .then(cert => ({cert, ca: ca_cert})) }

function createSelfSignedCertificate(subjects, ec) {
  if (ec == null)
    ec = ec_pem.generate('prime256v1')
  return openssl_req({subjects, self_sign: true}, ec)
    .then(cert => asTLSOptions(cert, ec)) }

function asTLSOptions(cert, ec) {
  if (ec == null)
    throw new Error("Parameter 'ec' is required and should be used to create cert")

  return Promise.resolve(cert).then(cert => 
    Object.defineProperties(
      {cert: cert.cert || cert, key: ec_pem.encodePrivateKey(ec)},
      {ec: {value: ec}}) )}


const example_subjects = {
  CN: 'example.com', // common name (required)
  C: 'us', // country	
  ST: 'colorado', // state
  L: 'colorado', // location
  O: 'example org', // organization
  OU: 'example org unit', // organizational unit
}

function openssl_subj_arg(subjects) {
  if (!subjects) return []
  if ('string' === typeof subjects)
    return ['-subj', `/CN=${subjects}`]

  subjects = Object.keys(subjects)
    .map(k => `/${k}=${subjects[k]}`)

  return ['-subj', subjects.join()] }


// openssl req -new -key /dev/stdin [-x509] -subj "/CN=example.com" < «ec private key»
function openssl_req(options, ec) {
  if ('string' === typeof options) 
    options = {self_sign: true, subjects: {CN: options}}

  let args = ['req', '-new', '-key', '/dev/stdin']

  if (options.self_sign)
    args.push('-x509', '-days', options.days || 1)

  args = args.concat(openssl_subj_arg(options.subjects))

  args = args.filter(e => e)
  return openssl_cmd(args, {input: ec_pem.encodePrivateKey(ec)})
    .then(resp => resp.stdout) }


// openssl x509 -req -in «/tmp/.../csr.pem» -CAkey /dev/stdin < «ec private key»
function openssl_x509(csr, ca_key, ca_cert, options) {
  if (!options) options = {}
  if (!ca_cert)
    throw new Error("Parameter 'ca_cert' is required")

  return tmpfile(csr.csr || csr).then(tmp_csr =>
    tmpfile(ca_cert.cert || ca_cert).then(tmp_ca_cert => {
      let args = ['x509', '-req', '-days', options.days || 1, '-set_serial', options.serial || '00']
      args.push('-in', tmp_csr.path, '-CA', tmp_ca_cert.path, '-CAkey', '/dev/stdin')
      return openssl_cmd(args, {input: ec_pem.encodePrivateKey(ca_key)})
        .then(resp => {
          tmp_csr.cleanup()
          tmp_ca_cert.cleanup()
          return resp.stdout }) }))}


function openssl_cmd(args, options) {
  return spawn_cmd('openssl', args, options) }


// child_process.spawn with {stdout, stderr}, Promises
function spawn_cmd(comand, args, options) {
  if (!options) options = {}

  return new Promise((resolve, reject) => {
    let io = {stdout: [], stderr: []}
    let finish = () => 
      ({stdout: io.stdout.join(''), stderr: io.stderr.join('')})

    let child = child_process.spawn(comand, args,
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
  new Promise((resolve, reject) =>
    tmp.file((err, path, fd, cleanup) => {
      if (err) return reject(err)
      _fs_write(fd, content)
        .catch(err => (_fs_close(fd), reject(err)))
        .then(() => _fs_close(fd))
        .then(() => resolve({path, cleanup}), reject) }))



Object.assign(exports, {
  generateCertificateSigningRequest, generateCSR: generateCertificateSigningRequest,
  createSignedCertificate, createSelfSignedCertificate, asTLSOptions,
  openssl_req, openssl_x509, openssl_cmd,
  openssl_subj_arg,
  spawn_cmd, 
})

