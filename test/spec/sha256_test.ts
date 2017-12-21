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
// \brief SHA256 test cases
//
///////////////////////////////////////////////////////////////////////////////

import {SHA256} from '../../src/sha256';
import {Convert} from '../../src/base';
import {vector} from './sha256_vectors';

import { expect, assert } from 'chai';
import 'mocha';


describe('SHA256', () => {
  let sha = new SHA256();

  describe('hash', () => {
    it('check testvectors (' + vector.length + ')', () => {
      for (let i = 0; i < vector.length; i++) {
        let pt = vector[i][0];
        let ct = vector[i][1];
        expect(Convert.bin2hex(sha.hash(Convert.str2bin(pt)))).to.deep.equal(ct);
      }
    });
  });

  describe('update', () => {
    it('check testvectors (' + vector.length + ')', () => {
      for (var i = 0; i < vector.length; i++) {
        let pt = vector[i][0];
        let ct = vector[i][1];
        sha.init();
        for (let j = 0; j < pt.length; j++) {
          sha.update(Convert.str2bin(pt.charAt(j)));
        }
        expect(Convert.bin2hex(sha.digest())).to.deep.equal(ct);
      }
    });
  });

  /**
   * This test is taken out of the sjcl project, using an ad-hoc iterative technique.
   * This uses a string buffer which has n characters on the nth iteration.
   * Each iteration, the buffer is hashed and the hash is converted to a string.
   * The first two characters of the string are prepended to the buffer, then the
   * last character of the buffer is removed. This way, neither the beginning nor
   * the end of the buffer is fixed.
   *
   * The hashes from each output step are also hashed together into one final hash.
   * This is compared against a final hash which was computed with SSL.
   */
  describe('iteration', () => {
    it('check testvector', () => {
      let cumulative = new SHA256();
      let toBeHashed = "", hash;
      for (let i = 0; i < 10; i++) {
        for (let n = 100 * i; n < 100 * (i + 1); n++) {
          hash = Convert.bin2hex(sha.hash(Convert.str2bin(toBeHashed)));
          cumulative.update(Convert.str2bin(hash));
          toBeHashed = (hash.substring(0, 2) + toBeHashed).substring(0, n + 1);
        }
      }
      hash = Convert.bin2hex(cumulative.digest());
      expect(hash).to.equal('f305c76d5d457ddf04f1927166f5e13429407049a5c5f29021916321fcdcd8b4');
    });
  });

  describe('selftest', () => {
    it('check selftest', () => {
      assert.equal(sha.selftest(), true);
    });
  });

});
