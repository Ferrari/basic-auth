'use strict'

var jwt = require('jsonwebtoken')

/**
 * Module exports.
 * @public
 */

module.exports = auth

/**
 * Parse the Authorization header field of a request.
 *
 * @param {object} req
 * @param {string} secret for JWT
 * @return {Mixed} JWT payload
 * @public
 */

function auth(req, secret, opts) {
  if (!req) {
    throw new TypeError('argument req is required')
  }

  if (typeof req !== 'object') {
    throw new TypeError('argument req is required to be an object')
  }

  // get header
  var header = getAuthorization(req.req || req)

  // parse header
  var regexp
  if (opts && opts.authSchema) {
    regexp = new RegExp(opts.authSchema + '\\s+(\\S+)', 'i')
  } else {
    regexp = new RegExp('[JWT|jwt]+\\s+(\\S+)', 'i')
  }
  var match = regexp.exec(header || '')

  if (!match) {
    return
  }

  // return jwt encode payload
  try {
    return (opts)
      ? jwt.verify(match[1], secret, opts)
      : jwt.verify(match[1], secret)
  } catch (err) {
    throw err
  }
}

/**
 * Get the Authorization header from request object.
 * @private
 */

function getAuthorization(req) {
  if (!req.headers || typeof req.headers !== 'object') {
    throw new TypeError('argument req is required to have headers property')
  }

  return req.headers.authorization
}
