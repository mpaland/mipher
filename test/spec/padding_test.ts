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
// \brief Padding test cases
//
///////////////////////////////////////////////////////////////////////////////

import { PKCS7 } from '../../src/padding';
import { Convert } from '../../src/base';

import { expect, assert } from 'chai';
import 'mocha';


describe('Padding', () => {
  let padding = new PKCS7();

  describe('PKCS7', () => {
    it('check pad and strip', () => {
      for (let bs = 2; bs < 32; bs += 2) {
        for (let len = 0; len < 128; len++) {
          var bin = new Uint8Array(len);
          for (let i = 0; i < len; i++) {
            bin[i] = Math.floor(Math.random() * 256);
          }
          let bin2 = new Uint8Array(bin);
          let b2 = padding.pad(bin, bs);
          assert.ok(b2.length % bs === 0);
          let b3 = padding.strip(b2);
          assert.deepEqual(b3, bin2);
        }
      }
    });
  });

});
