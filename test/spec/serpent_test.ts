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
// \brief Serpent test cases
//
///////////////////////////////////////////////////////////////////////////////

import { Serpent, Serpent_CBC_PKCS7 } from '../../src/serpent';
import { Convert } from '../../src/base';
import { vector, vectorMonteCarloEncrypt, vectorMonteCarloDecrypt, vectorCBC_PKCS7 } from './serpent_vectors';

import chai = require('chai');
var expect = chai.expect;
var assert = chai.assert;


describe('Serpent', () => {
  let serpent = new Serpent();

  describe('encrypt', () => {
    it('check testvectors (' + vector.length + ')', () => {
      for (let i = 0; i < vector.length; i++) {
        let key = Convert.hex2bin(vector[i].key);
        let pt  = Convert.hex2bin(vector[i].pt);
        let ct  = Convert.hex2bin(vector[i].ct);
        expect(serpent.encrypt(key, pt)).to.deep.equal(ct);
      }
    });
  });

  describe('decrypt', () => {
    it('check testvectors (' + vector.length + ')', () => {
      for (let i = 0; i < vector.length; i++) {
        let key = Convert.hex2bin(vector[i].key);
        let pt  = Convert.hex2bin(vector[i].pt);
        let ct  = Convert.hex2bin(vector[i].ct);
        expect(serpent.decrypt(key, ct)).to.deep.equal(pt);
      }
    });
  });

  describe('encrypt - Monte Carlo 10000 rounds', () => {
    it('check testvectors (' + vectorMonteCarloEncrypt.length + ')', () => {
      for (let i = 0; i < vectorMonteCarloEncrypt.length; i++) {
        let key = Convert.hex2bin(vectorMonteCarloEncrypt[i].key);
        let pt  = Convert.hex2bin(vectorMonteCarloEncrypt[i].pt);
        let ct  = Convert.hex2bin(vectorMonteCarloEncrypt[i].ct);

        for (let n = 0; n < 10000; n++) {
          pt = serpent.encrypt(key, pt);
        }

        expect(pt).to.deep.equal(ct);
      }
    });
  });

  describe('decrypt - Monte Carlo 10000 rounds', () => {
    it('check testvectors (' + vectorMonteCarloDecrypt.length + ')', () => {
      for (let i = 0; i < vectorMonteCarloDecrypt.length; i++) {
        let key = Convert.hex2bin(vectorMonteCarloDecrypt[i].key);
        let pt  = Convert.hex2bin(vectorMonteCarloDecrypt[i].pt);
        let ct  = Convert.hex2bin(vectorMonteCarloDecrypt[i].ct);

        for (let n = 0; n < 10000; n++) {
          ct = serpent.decrypt(key, ct);
        }

        expect(ct).to.deep.equal(pt);
      }
    });
  });

  describe('CBC-PKCS7', () => {
    it('check testvectors (' + vectorCBC_PKCS7.length + ')', () => {
      let serpent_c = new Serpent_CBC_PKCS7();

      for (let i = 0; i < vectorCBC_PKCS7.length; i++) {
        let key = Convert.hex2bin(vectorCBC_PKCS7[i].key);
        let pt  = Convert.hex2bin(vectorCBC_PKCS7[i].pt);
        let iv  = Convert.hex2bin(vectorCBC_PKCS7[i].iv);
        let ct  = serpent_c.encrypt(key, pt, iv);
        var pt2 = serpent_c.decrypt(key, ct, iv);

        expect(pt2).to.deep.equal(pt);
      }
    });
  });

  describe('selftest', () => {
    it('check selftest', () => {
      assert.equal(serpent.selftest(), true);
    });
  });

});
