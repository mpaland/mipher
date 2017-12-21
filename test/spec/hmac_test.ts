///////////////////////////////////////////////////////////////////////////////
// \author (c) Marco Paland (marco@paland.com)
//             2015, PALANDesign Hannover, Germany
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
// \brief HMAC test cases
//
///////////////////////////////////////////////////////////////////////////////

import { HMAC, HMAC_SHA1, HMAC_SHA256, HMAC_SHA512 } from '../../src/hmac';
import { SHA256 } from '../../src/sha256';
import { Convert } from '../../src/base';
import { vector } from './hmac_vectors';

import { expect, assert } from 'chai';
import 'mocha';


describe('HMAC', () => {
  describe('input unaltered', () => {
    it('check testvectors (' + vector.length + ')', () => {
      for (let i = 0; i < vector.length; i++) {
        let key  = Convert.hex2bin(vector[i].key);
        let data = Convert.hex2bin(vector[i].data);
        let mac  = (new HMAC(new SHA256())).hash(key, data);
        expect(Convert.bin2hex(key)).to.deep.equal(vector[i].key);
        expect(Convert.bin2hex(data)).to.deep.equal(vector[i].data);
      }
    });
  });

  describe('HMAC-SHA1', () => {
    let hmac_sha1 = new HMAC_SHA1();
    it('check testvectors (' + vector.length + ')', () => {
      for (let i = 0; i < vector.length; i++) {
        let key  = vector[i].key;
        let data = vector[i].data;
        let mac  = vector[i].mac1;
        expect(hmac_sha1.hash(Convert.hex2bin(key), Convert.hex2bin(data))).to.deep.equal(Convert.hex2bin(mac));
      }
    });
  });

  describe('HMAC-SHA256', () => {
    let hmac_sha256 = new HMAC_SHA256();
    it('check testvectors (' + vector.length + ')', () => {
      for (let i = 0; i < vector.length; i++) {
        let key  = vector[i].key;
        let data = vector[i].data;
        let mac  = vector[i].mac256;
        expect(hmac_sha256.hash(Convert.hex2bin(key), Convert.hex2bin(data))).to.deep.equal(Convert.hex2bin(mac));
      }
    });
  });

  describe('HMAC-SHA512', () => {
    let hmac_sha512 = new HMAC_SHA512();
    it('check testvectors (' + vector.length + ')', () => {
      for (let i = 0; i < vector.length; i++) {
        let key  = vector[i].key;
        let data = vector[i].data;
        let mac  = vector[i].mac512;
        expect(hmac_sha512.hash(Convert.hex2bin(key), Convert.hex2bin(data))).to.deep.equal(Convert.hex2bin(mac));
      }
    });
  });

});
