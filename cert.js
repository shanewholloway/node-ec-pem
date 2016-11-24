'use strict'
const ec_pem = require('./ec_pem')
const child_process = require('child_process')

function generateCSR(subjects, ec) {
  if (ec == null)
    ec = ec_pem.generate('prime256v1')
  return openssl_req({subjects}, ec)
    .then(csr => 
      Object.defineProperties({csr},
        {ec: {value: ec}}) )}

function createSelfSignedCertificate(subjects, ec) {
  if (ec == null)
    ec = ec_pem.generate('prime256v1')
  return openssl_req({subjects, self_sign: true}, ec)
    .then(cert =>
      Object.defineProperties(
        {cert, key: ec_pem.encodePrivateKey(ec)},
        {ec: {value: ec}}) )}


const example_subjects = {
  CN: 'example.com', // common name (required)
  C: 'us', // country	
  ST: 'colorado', // state
  L: 'colorado', // location
  O: 'example org', // organization
  OU: 'example org unit', // organizational unit
}

// openssl req -new -key /dev/stdin [-x509] -subj "/CN=example.com" < «ec private key»
function openssl_req(options, ec) {
  if ('string' === typeof options) 
    options = {self_sign: true, subjects: {CN: options}}

  let subjects = options.subjects
  if ('string' === typeof subjects) 
    subjects = {CN: subjects}
  else if (!subjects) 
    throw new Error("Subjects parameter is required. (e.g. {CN:'example.com'})")

  const subj = Object.keys(subjects).map(k => `/${k}=${subjects[k]}`).join()

  let args = ['req', '-new', '-key', '/dev/stdin', '-subj', subj]
  if (options.self_sign)
    args.push('-x509', '-days', options.days || 1)
  args = args.filter(e => e)

  return openssl_cmd(args, {input: ec_pem.encodePrivateKey(ec)})
    .then(resp => resp.stdout) }


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


Object.assign(exports, {
  generateCSR, createSelfSignedCertificate,
  openssl_req, openssl_cmd, spawn_cmd, 
})

