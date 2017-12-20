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
// \brief PBKDF2 test cases
//
///////////////////////////////////////////////////////////////////////////////

import { PBKDF2 } from '../../src/pbkdf2';
import { Convert } from '../../src/base';
import { HMAC } from '../../src/hmac';
import { SHA256 } from '../../src/sha256';
import { vector } from './pbkdf2_vectors';

import chai = require('chai');
var expect = chai.expect;
var assert = chai.assert;


describe('PBKDF2', () => {
  describe('HMAC-SHA256', () => {
    it('check testvectors (' + vector.length + ')', () => {
      for (let i = 0; i < vector.length; i++) {
        let pbkdf2_sha256 = new PBKDF2(new HMAC(new SHA256()), vector[i].c);
        let key  = Convert.str2bin(vector[i].key);
        let salt = Convert.str2bin(vector[i].salt);
        let mac  = pbkdf2_sha256.hash(key, salt, Convert.hex2bin(vector[i].sha256).length);
        assert.deepEqual(mac, Convert.hex2bin(vector[i].sha256));
      }
    });
  });

  describe('selftest', () => {
    it('check selftest', () => {
      let pbkdf2_sha256 = new PBKDF2(new HMAC(new SHA256()));
      assert.equal(pbkdf2_sha256.selftest(), true);
    });
  });

});
