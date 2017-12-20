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
// \brief curve25519 and ed25519 test cases
//
///////////////////////////////////////////////////////////////////////////////

import { Curve25519, Ed25519 } from '../../src/x25519';
import { Convert } from '../../src/base';
import { generate_vector, random_vector, original_vector, ed25519_vector } from './x25519_vectors';

import chai = require('chai');
var expect = chai.expect;
var assert = chai.assert;


describe('curve25519', () => {
  let x25519  = new Curve25519();
  let ed25519 = new Ed25519();

  describe('x25519 - key generation (KAT)', () => {
    it('check testvectors (' + generate_vector.length + ')', () => {
      for (let i = 0; i < generate_vector.length; i++) {
        let sk = Convert.hex2bin(generate_vector[i][0]);
        let pk = Convert.hex2bin(generate_vector[i][1]);
        let x  = x25519.generateKeys(sk).pk;
        expect(x).to.deep.equal(pk);
      }
    });
  });

  describe('x25519 - key generation (Monte Carlo Test)', () => {
    it('check testvectors (' + generate_vector.length + ')', () => {
      // ref to https://code.google.com/p/go/source/browse/curve25519/curve25519_test.go?repo=crypto
      let input  = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      let result = new Uint8Array([0x89, 0x16, 0x1f, 0xde, 0x88, 0x7b, 0x2b, 0x53, 0xde, 0x54, 0x9a, 0xf4, 0x83, 0x94, 0x01, 0x06, 0xec, 0xc1, 0x14, 0xd6, 0x98, 0x2d, 0xaa, 0x98, 0x25, 0x6d, 0xe2, 0x3b, 0xdf, 0x77, 0x66, 0x1a]);
      for (let i = 0; i < 200; i++) {
        let keys = x25519.generateKeys(input);
        input = keys.pk;
      }
      expect(input).to.deep.equal(result);
    });
  });

  describe('x25519 - scalarMult', () => {
    it('check original testvectors (' + original_vector.length + ')', function (done) {
      this.timeout(10000);
      for (let i = 0; i < original_vector.length; i++) {
        let sk  = Convert.hex2bin(original_vector[i][0]);
        let pk  = Convert.hex2bin(original_vector[i][1]);
        let out = Convert.hex2bin(original_vector[i][2]);
        expect(x25519.scalarMult(sk, pk)).to.deep.equal(out);
      }
      done();
    });

    it('check random testvectors (' + original_vector.length + ')', function (done) {
      this.timeout(10000);
      for (let i = 0; i < random_vector.length; i++) {
        let pk1 = Convert.base642bin(random_vector[i][0]);
        let sk1 = Convert.base642bin(random_vector[i][1]);
        let pk2 = Convert.base642bin(random_vector[i][2]);
        let sk2 = Convert.base642bin(random_vector[i][3]);
        let out = Convert.base642bin(random_vector[i][4]);
        sk1[ 0] &= 0xf8;
        sk1[31] &= 0x3f;
        sk1[31] |= 0x40;
        sk2[ 0] &= 0xf8;
        sk2[31] &= 0x3f;
        sk2[31] |= 0x40;
        expect(x25519.generateKeys(sk1).pk).to.deep.equal(pk1);
        expect(x25519.generateKeys(sk2).pk).to.deep.equal(pk2);
        expect(x25519.scalarMult(sk1, pk2)).to.deep.equal(out);
        expect(x25519.scalarMult(sk2, pk1)).to.deep.equal(out);
      }
      done();
    });
  });

  describe('x25519 - selftest', () => {
    it('check selftest', () => {
      assert.equal(x25519.selftest(), true);
    });
  });

  describe('ed25519 - key generation', () => {
    it('check testvectors (' + ed25519_vector.length + ')', function (done) {
      this.timeout(10000);
      for (var i = 0; i < 256; i++) {
        var sk = Convert.hex2bin(ed25519_vector[i].sk);
        var pk = Convert.hex2bin(ed25519_vector[i].pk);
        expect(ed25519.generateKeys(sk).pk).to.deep.equal(pk);
      }
      done();
    });
  });

  describe('ed25519 - signing', () => {
    it('check testvectors (' + ed25519_vector.length + ')', function (done) {
      this.timeout(10000);
      for (let i = 0; i < 256; i++) {
        let sk = Convert.hex2bin(ed25519_vector[i].sk);
        let pk = Convert.hex2bin(ed25519_vector[i].pk);
        let m  = Convert.hex2bin(ed25519_vector[i].m);
        let s  = Convert.hex2bin(ed25519_vector[i].s);
        expect(ed25519.sign(m, sk, pk)).to.deep.equal(s);
      }
      done();
    });
  });

  describe('ed25519 - verify', () => {
    it('check testvectors (' + ed25519_vector.length + ')', function (done) {
      this.timeout(10000);
      for (let i = 0; i < 256; i++) {
        let pk = Convert.hex2bin(ed25519_vector[i].pk);
        let m  = Convert.hex2bin(ed25519_vector[i].m);
        let s  = Convert.hex2bin(ed25519_vector[i].s);
        assert.ok(ed25519.verify(m, pk, s), "passed");
      }

      for (let i = 0; i < 128; i++) {
        let pk = Convert.hex2bin(ed25519_vector[i].pk);
        let m  = Convert.hex2bin(ed25519_vector[i].m);
        let s  = Convert.hex2bin(ed25519_vector[i].s);
        s[i % 64] ^= 0x01;
        assert.notOk(ed25519.verify(m, pk, s), "passed");
      }

      // signature length test
      let pk = Convert.hex2bin(ed25519_vector[20].pk);
      let m  = Convert.hex2bin(ed25519_vector[20].m);
      let s  = Convert.hex2bin(ed25519_vector[20].s);
      assert.notOk(ed25519.verify(m, pk, s.subarray(0, 63)), "passed");
      done();
    });
  });

  describe('ed25519 - selftest', () => {
    it('check selftest', () => {
      assert.equal(ed25519.selftest(), true);
    });
  });

});
