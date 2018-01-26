# mipher

[![npm](https://img.shields.io/npm/v/mipher.svg)](https://www.npmjs.com/package/mipher)
[![npm](https://img.shields.io/npm/dt/mipher.svg)](https://www.npmjs.com/package/mipher)
[![Github Issues](https://img.shields.io/github/issues/mpaland/mipher.svg)](http://github.com/mpaland/mipher/issues)
[![Github Releases](https://img.shields.io/github/release/mpaland/mipher.svg)](https://github.com/mpaland/mipher/releases)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/mpaland/mipher/master/LICENSE)

**M**obile C**ipher** crypto library written in clean TypeScript


## Highligths and design goals
There are a lot of crypto libs in JS around, but I needed a clean, lightweight, reliable, fast and simple lib for mobile devices in TypeScript. That's **mipher**.  
A collection of common crypto algorithms, optimized for speed, security and size.

 - Only usage of modern typed arrays like `Uint8Array` and `Uint32Array` as message/data types
 - Fast and simple, no dependencies
 - Own crypto random generator (using a FORTUNA implementation)
 - Extensive passing test suite
 - MIT license


## Supported algorithms
 - AES
 - Serpent
 - Chacha20
 - Curve25519, Ed25519
 - HMAC
 - PBKDF2
 - SHA-1, SHA-256, SHA-512, SHA-3, Keccak, SHAKE
 - UUID
 - Random generator
 - Blockmodes (ECB, CBC, CTR)
 - Padding (PKCS5, PKCS7, zero padding)
 - Format converter (bin, number, hex, base64, string)
 - Utils (xor, cryptocompare etc.)


## Usage
Import the mipher module as `mipher` and create your according crypto object:
```typescript
import * as mipher from 'mipher';

let aes = new mipher.AES();
let ct  = aes.encrypt(key, pt);
```

## Test suite
mipher is using the mocha test suite for testing.
To do all tests just run `npm run test`.


## Contributing
If you find any bugs, have any comments, improvements or suggestions:

1. Create an issue and describe your idea
2. [Fork it](https://github.com/mpaland/mipher/fork)
3. Create your feature branch (`git checkout -b my-new-feature`)
4. Commit your changes (`git commit -am 'Add some feature'`)
5. Publish the branch (`git push origin my-new-feature`)
6. Create a new pull request
7. Profit! :white_check_mark:


## License
mipher is written under the [MIT license](http://www.opensource.org/licenses/MIT).