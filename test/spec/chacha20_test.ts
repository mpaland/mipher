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
// \brief chacha20 test cases
//
///////////////////////////////////////////////////////////////////////////////

import { ChaCha20 } from '../../src/chacha20';
import { Convert } from '../../src/base';
import { vector } from './chacha20_vectors';

import { expect, assert } from 'chai';
import 'mocha';


describe('ChaCha20', () => {
  var chacha = new ChaCha20();

  describe('encrypt', () => {
    it('check testvectors (' + vector.length + ')', () => {
      for (var i = 0; i < vector.length; i++) {
        var v = vector[i];
        var pt = new Uint8Array(v.ct.length / 2);
        if (typeof v.pt !== 'undefined') {
          pt = Convert.hex2bin(v.pt);
        }
        var out = chacha.encrypt(Convert.hex2bin(v.key), pt, Convert.hex2bin(v.iv), v.ibc);
        expect(out).to.deep.equal(Convert.hex2bin(v.ct));
      }
    });
  });

  describe('decrypt', () => {
    it('check testvectors (' + vector.length + ')', () => {
      for (var i = 0; i < vector.length; i++) {
        var v = vector[i];
        var pt = new Uint8Array(v.ct.length / 2);
        if (typeof v.pt !== 'undefined') {
          pt = Convert.hex2bin(v.pt);
        }
        var out = chacha.decrypt(Convert.hex2bin(v.key), Convert.hex2bin(v.ct), Convert.hex2bin(v.iv), v.ibc);
        expect(out).to.deep.equal(pt);
      }
    });
  });

});
