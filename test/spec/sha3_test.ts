///////////////////////////////////////////////////////////////////////////////
// \author (c) Marco Paland (marco@paland.com)
//             2015-2016, PALANDesign Hannover, Germany
//
// \license The MIT License (MIT)
//
// This file is part of the mipher crypto library.
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// \brief SHA3 and SHAKE test cases
//
///////////////////////////////////////////////////////////////////////////////

import { SHA3_256, SHA3_512, SHAKE128, SHAKE256 } from '../../src/sha3';
import { Convert } from '../../src/base';
import { sha3_256_vector } from './sha3_256_vectors';
import { sha3_512_vector } from './sha3_512_vectors';
import { shake128_vector } from './shake128_vectors';
import { shake256_vector } from './shake256_vectors';
import { shake128_vector_long } from './shake128_vectors_long';
import { shake256_vector_long } from './shake256_vectors_long';


import chai = require('chai');
var expect = chai.expect;
var assert = chai.assert;


describe('SHA3-256', () => {
  let sha = new SHA3_256();

  describe('hash', () => {
    it('check testvectors (' + sha3_256_vector.length + ')', () => {
      for (let i = 0; i < sha3_256_vector.length; i++) {
        let pt = sha3_256_vector[i][0];
        let ct = sha3_256_vector[i][1];
        expect(Convert.bin2hex(sha.hash(Convert.hex2bin(pt)), true)).to.deep.equal(ct);
      }
    });
  });

  describe('update', () => {
    it('check testvectors (' + sha3_256_vector.length + ')', () => {
      for (let i = 0; i < sha3_256_vector.length; i++) {
        let pt = sha3_256_vector[i][0];
        let ct = sha3_256_vector[i][1];
        sha.init();
        for (let j = 0; j < pt.length; j += 2) {
          sha.update(Convert.hex2bin(pt.substr(j, 2)));
        }
        expect(Convert.bin2hex(sha.digest(), true)).to.deep.equal(ct);
      }
    });
  });
});


describe('SHA3-512', () => {
  let sha = new SHA3_512();

  describe('hash', () => {
    it('check testvectors (' + sha3_512_vector.length + ')', () => {
      for (let i = 0; i < sha3_512_vector.length; i++) {
        let pt = sha3_512_vector[i][0];
        let ct = sha3_512_vector[i][1];
        expect(Convert.bin2hex(sha.hash(Convert.hex2bin(pt)), true)).to.deep.equal(ct);
      }
    });
  });

  describe('update', () => {
    it('check testvectors (' + sha3_512_vector.length + ')', () => {
      for (var i = 0; i < sha3_512_vector.length; i++) {
        let pt = sha3_512_vector[i][0];
        let ct = sha3_512_vector[i][1];
        sha.init();
        for (let j = 0; j < pt.length; j += 2) {
          sha.update(Convert.hex2bin(pt.substr(j, 2)));
        }
        expect(Convert.bin2hex(sha.digest(), true)).to.deep.equal(ct);
      }
    });
  });
});


describe('SHAKE128-256', () => {
  let sha = new SHAKE128(256);

  describe('hash', () => {
    it('check testvectors (' + shake128_vector.length + ')', () => {
      for (let i = 0; i < shake128_vector.length; i++) {
        let pt = shake128_vector[i][0];
        let ct = shake128_vector[i][1];
        expect(Convert.bin2hex(sha.hash(Convert.hex2bin(pt)), true)).to.deep.equal(ct);
      }
    });
  });

  describe('update', () => {
    it('check testvectors (' + shake128_vector.length + ')', () => {
      for (var i = 0; i < shake128_vector.length; i++) {
        let pt = shake128_vector[i][0];
        let ct = shake128_vector[i][1];
        sha.init();
        for (let j = 0; j < pt.length; j += 2) {
          sha.update(Convert.hex2bin(pt.substr(j, 2)));
        }
        expect(Convert.bin2hex(sha.digest(), true)).to.deep.equal(ct);
      }
    });
  });
});


describe('SHAKE256-512', () => {
  let sha = new SHAKE256(512);

  describe('hash', () => {
    it('check testvectors (' + shake256_vector.length + ')', () => {
      for (let i = 0; i < shake256_vector.length; i++) {
        let pt = shake256_vector[i][0];
        let ct = shake256_vector[i][1];
        expect(Convert.bin2hex(sha.hash(Convert.hex2bin(pt)), true)).to.deep.equal(ct);
      }
    });
  });

  describe('update', () => {
    it('check testvectors (' + shake256_vector.length + ')', () => {
      for (var i = 0; i < shake256_vector.length; i++) {
        let pt = shake256_vector[i][0];
        let ct = shake256_vector[i][1];
        sha.init();
        for (let j = 0; j < pt.length; j += 2) {
          sha.update(Convert.hex2bin(pt.substr(j, 2)));
        }
        expect(Convert.bin2hex(sha.digest(), true)).to.deep.equal(ct);
      }
    });
  });
});
