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
// \brief AES test cases
//
///////////////////////////////////////////////////////////////////////////////

import { AES, AES_CBC_PKCS7 } from '../../src/aes';
import { Convert } from '../../src/base';
import { vector128, vector192, vector256, vectorCBC_PKCS7 } from './aes_vectors';

import { expect, assert } from 'chai';
import 'mocha';


describe('AES', () => {
  var aes = new AES();

  describe('encrypt', () => {
    it('check 128 bit testvectors (' + vector128.length + ')', () => {
      for (var i = 0; i < vector128.length; i++) {
        var key = Convert.hex2bin(vector128[i].key);
        var pt  = Convert.hex2bin(vector128[i].pt);
        var ct  = Convert.hex2bin(vector128[i].ct);
        expect(aes.encrypt(key, pt)).to.deep.equal(ct);
      }
    });

    it('check 192 bit testvectors (' + vector192.length + ')', () => {
      for (var i = 0; i < vector192.length; i++) {
        var key = Convert.hex2bin(vector192[i].key);
        var pt  = Convert.hex2bin(vector192[i].pt);
        var ct  = Convert.hex2bin(vector192[i].ct);
        expect(aes.encrypt(key, pt)).to.deep.equal(ct);
      }
    });

    it('check 256 bit testvectors (' + vector256.length + ')', () => {
      for (var i = 0; i < vector256.length; i++) {
        var key = Convert.hex2bin(vector256[i].key);
        var pt  = Convert.hex2bin(vector256[i].pt);
        var ct  = Convert.hex2bin(vector256[i].ct);
        expect(aes.encrypt(key, pt)).to.deep.equal(ct);
      }
    });
  });

  describe('decrypt', () => {
    it('check 128 bit testvectors (' + vector256.length + ')', () => {
      for (var i = 0; i < vector128.length; i++) {
        var key = Convert.hex2bin(vector128[i].key);
        var pt  = Convert.hex2bin(vector128[i].pt);
        var ct  = Convert.hex2bin(vector128[i].ct);
        expect(aes.decrypt(key, ct)).to.deep.equal(pt);
      }
    });

    it('check 192 bit testvectors (' + vector192.length + ')', () => {
      for (var i = 0; i < vector192.length; i++) {
        var key = Convert.hex2bin(vector192[i].key);
        var pt  = Convert.hex2bin(vector192[i].pt);
        var ct  = Convert.hex2bin(vector192[i].ct);
        expect(aes.decrypt(key, ct)).to.deep.equal(pt);
      }
    });

    it('check 256 bit testvectors (' + vector256.length + ')', () => {
      for (var i = 0; i < vector256.length; i++) {
        var key = Convert.hex2bin(vector256[i].key);
        var pt  = Convert.hex2bin(vector256[i].pt);
        var ct  = Convert.hex2bin(vector256[i].ct);
        expect(aes.decrypt(key, ct)).to.deep.equal(pt);
      }
    });
  });

  describe('CBC-PKCS7', () => {
    var aes_c = new AES_CBC_PKCS7();
    it('check CBC-PKCS7 testvectors (' + vectorCBC_PKCS7.length + ')', () => {
      for (var i = 0; i < vectorCBC_PKCS7.length; i++) {
        var key = Convert.hex2bin(vectorCBC_PKCS7[i].key);
        var pt  = Convert.hex2bin(vectorCBC_PKCS7[i].pt);
        var iv  = Convert.hex2bin(vectorCBC_PKCS7[i].iv);
        var ct  = aes_c.encrypt(key, pt, iv);
        var pt2 = aes_c.decrypt(key, ct, iv);
        expect(pt2).to.deep.equal(pt);
      }
    });
  });

  describe('selftest', () => {
    it('check selftest', () => {
      assert.equal(aes.selftest(), true);
    });
  });

});
