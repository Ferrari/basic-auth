# jwt-parser

[![NPM Version][npm-image]][npm-url]
[![NPM Downloads][downloads-image]][downloads-url]
[![Node.js Version][node-version-image]][node-version-url]
[![Build Status][travis-image]][travis-url]

Generic JWT Authorization header field parser for whatever.

## Installation

```
$ npm install jwt-parser
```

## API

```js
var auth = require('jwt-parser')
```

### auth(req, secret)

Get the JWT payload from the given request. JWT `secret` also required so 
it can decode and get payload correctly. The `Authorization`
header is parsed and if the header is invalid, `undefined` is returned,
otherwise will return decode jwt payload.

## Example

```js
var auth = require('jwt-parser');
var user = auth(req, secret);
```
# License

[MIT](LICENSE)

[npm-image]: https://img.shields.io/npm/v/jwt-parser.svg
[npm-url]: https://npmjs.org/package/jwt-parser
[node-version-image]: https://img.shields.io/node/v/jwt-parser.svg
[node-version-url]: https://nodejs.org/en/download
[travis-image]: https://img.shields.io/travis/Ferrari/jwt-parser/master.svg
[travis-url]: https://travis-ci.org/Ferrari/jwt-parser
[downloads-image]: https://img.shields.io/npm/dm/jwt-parser.svg
[downloads-url]: https://npmjs.org/package/jwt-parser
