///////////////////////////////////////////////////////////////////////////////
// \author (c) Marco Paland (marco@paland.com)
//             2015-2018, PALANDesign Hannover, Germany
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
// \brief base function test cases
//
///////////////////////////////////////////////////////////////////////////////

import { Convert, Util } from '../../src/base';

import { expect, assert } from 'chai';
import 'mocha';


declare var atob;
declare var btoa;

describe('Convert', () => {

  describe('hex2bin', () => {
    it('check hex to bin', () => {
      for (let strlen = 0; strlen < 256; strlen++) {
        let exp = new Uint8Array(strlen);
        let inp = '';
        for (let i = 0; i < strlen; i++) {
          inp += (i < 16 ? '0' : '') + i.toString(16);
          exp[i] = i;
        }
        expect(Convert.hex2bin(inp)).to.deep.equal(exp);
      }
    });
  });

  describe('bin2hex', () => {
    it('check bin to hex', () => {
      for (let strlen = 0; strlen < 256; strlen++) {
        let inp = new Uint8Array(strlen);
        let expL = '';
        let expU = '';
        for (let i = 0; i < strlen; i++) {
          expL += (i < 16 ? '0' : '') + i.toString(16).toLowerCase();
          expU += (i < 16 ? '0' : '') + i.toString(16).toUpperCase();
          inp[i] = i;
        }
        expect(Convert.bin2hex(inp)).to.deep.equal(expL);
        expect(Convert.bin2hex(inp, true)).to.deep.equal(expU);
      }
    });
  });

  describe('base642bin', () => {
    it('check base64 to bin ' + (typeof atob === 'undefined' ? '(atob not avail)' : '(using atob)'), () => {
      for (let i = 0; i < base64Vector.length; i++) {
        let pt = base64Vector[i][0];
        let ct = base64Vector[i][1];
        expect(Convert.base642bin(ct)).to.deep.equal(Convert.str2bin(pt));
      }
    });
    it('check base64 to bin (explicit no atob)', () => {
      for (let i = 0; i < base64Vector.length; i++) {
        let pt = base64Vector[i][0];
        let ct = base64Vector[i][1];
        if (typeof atob !== 'undefined') {
          atob = undefined;
        }
        expect(Convert.base642bin(ct)).to.deep.equal(Convert.str2bin(pt));
      }
    });
  });

  describe('bin2base64', () => {
    it('check bin to base64 ' + (typeof btoa === 'undefined' ? '(btoa not avail)' : '(using btoa)'), () => {
      for (let i = 0; i < base64Vector.length; i++) {
        let pt = base64Vector[i][0];
        let ct = base64Vector[i][1];
        expect(Convert.bin2base64(Convert.str2bin(pt))).to.deep.equal(ct);
      }
    });
    it('check bin to base64 (explicit no btoa)', () => {
      for (let i = 0; i < base64Vector.length; i++) {
        let pt = base64Vector[i][0];
        let ct = base64Vector[i][1];
        if (typeof btoa !== 'undefined') {
          btoa = undefined;
        }
        expect(Convert.bin2base64(Convert.str2bin(pt))).to.deep.equal(ct);
      }
    });
  });

  describe('bin2base64 - base642bin', () => {
    it('check base64 conversion', () => {
      for (let i = 0; i < 300; i++) {
        let bin = new Uint8Array(i);
        for (let n = 0; n < i; n++) {
          bin[n] = (Math.floor(Math.random() * 0xff));
        }
        expect(Convert.base642bin(Convert.bin2base64(bin))).to.deep.equal(bin);
      }
    });
  });

  describe('bin2base64 - base642bin URL', () => {
    it('check base64url conversion', () => {
      for (let i = 0; i < 300; i++) {
        let bin = new Uint8Array(i);
        for (let n = 0; n < i; n++) {
          bin[n] = (Math.floor(Math.random() * 0xff));
        }
        expect(bin).to.deep.equal(Convert.base642bin(Convert.bin2base64(bin, true)));
      }
    });
  });
});


describe('Util', () => {

  describe('clear', () => {
    it('should set all array elements to 0', () => {
      let bin = new Uint8Array(300);
      for (let n = 0; n < 300; n++) {
        bin[n] = (Math.floor(Math.random() * 0xff));
      }
      Util.clear(bin);
      let zero = new Uint8Array(300);
      expect(bin).to.deep.equal(zero);
    });
  });

  describe('xor', () => {
    it('should xor two arrays', () => {
      let bin1 = new Uint8Array(300);
      let bin2 = new Uint8Array(300);
      for (let n = 0; n < 300; n++) {
        bin1[n] = (Math.floor(Math.random() * 0xff));
        bin2[n] = (Math.floor(Math.random() * 0xff));
      }
      let xor1 = Util.xor(bin1, bin2);
      let xor2 = new Uint8Array(300);
      for (let n = 0; n < 300; n++) {
        xor2[n] = bin1[n] ^ bin2[n];
      }
      expect(xor1).to.deep.equal(xor2);
    });
  });

});


///////////////////////////////////////////////////////////////////////////////

const base64Vector = [
  ["", ""],
  ["f", "Zg=="],
  ["fo", "Zm8="],
  ["foo", "Zm9v"],
  ["foob", "Zm9vYg=="],
  ["fooba", "Zm9vYmE="],
  ["foobar", "Zm9vYmFy"],
  ["1234567890", "MTIzNDU2Nzg5MA=="],
  ["sQrs8KCz8r9o9kggoaUdQkY", "c1FyczhLQ3o4cjlvOWtnZ29hVWRRa1k="],
  ["1234567890abcdefghijklmnopqrstuvwxyz", "MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6"]
];
