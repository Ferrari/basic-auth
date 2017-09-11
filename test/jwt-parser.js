var assert = require('assert');
var auth = require('..');
var jwt = require('jsonwebtoken');
var secret = 'jwt-parser jwt sercert';

function request(payload) {
  return {
    headers: {
      authorization: (payload) ? 'JWT ' + jwt.sign(payload, secret) : ''
    }
  }
}

function expiredRequest(payload) {
  return {
    headers: {
      authorization: (payload) ? 'JWT ' + jwt.sign(payload, secret, { expiresIn: '1s' }) : ''
    }
  }
}

describe('auth(req)', function () {
  describe('arguments', function () {
    describe('req', function () {
      it('should be required', function () {
        assert.throws(auth, /argument req is required/)
      })

      it('should reject null', function () {
        assert.throws(auth.bind(null, null), /argument req is required/)
      })

      it('should reject an object without headers', function () {
        assert.throws(auth.bind(null, {}), /argument req is required/)
      })
    })
  })

  describe('with no Authorization field', function(){
    it('should return null', function(){
      var req = request();
      assert(null == auth(req));
    })
  })

  describe('with valid credentials', function(){
    it('should return string payload', function () {
      var req = request('basicZm9vOmJhcg')
      var payload = auth(req, secret)
      assert.equal(payload, 'basicZm9vOmJhcg')
    })

    it('should return object payload', function(){
      var req = request({name: 'foo', pass: 'bar'});
      var payload = auth(req, secret);
      assert.equal(payload.name, 'foo');
      assert.equal(payload.pass, 'bar');
    })
  })

  describe('with invalid token', function() {
    it('expired JWT token', function () {
      var req = expiredRequest({ name: 'testExpiredToken' })
      setTimeout(function() {
        assert.throws(auth(req, secret))
      }, 2000)
    })
  })
})
