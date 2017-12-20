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
// \brief UUID generator test cases
//
///////////////////////////////////////////////////////////////////////////////

import { UUID } from '../../src/uuid';
import { Convert } from '../../src/base';

import chai = require('chai');
var expect = chai.expect;
var assert = chai.assert;


describe('UUID', () => {
  var uuid = new UUID();

  describe('V1 generation', () => {
    it('check format', () => {
      let id1 = uuid.v1(new Uint8Array([0, 1, 2, 3, 4, 5]));
      let id2 = uuid.v1(new Uint8Array([1, 1, 2, 3, 4, 5]));
      assert.ok(typeof id1 !== 'undefined' && id1.length === 16, 'passed');
      assert.ok(typeof id2 !== 'undefined' && id2.length === 16, 'passed');
      assert.notDeepEqual(id1, id2, 'passed');
      let id3 = uuid.v1(new Uint8Array([0x55, 0xAA, 0, 1, 2, 3]));
      assert.ok(typeof id3 !== 'undefined' && id3.length === 16, 'passed');
      assert.ok(id3[10] === 0x55 && id3[11] === 0xAA, 'passed');
    });
  });

  describe('V4 generation', () => {
    it('check format', () => {
      let id1 = uuid.v4(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5]));
      let id2 = uuid.v4(new Uint8Array([1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5]));
      assert.ok(typeof id1 !== 'undefined' && id1.length === 16, 'passed');
      assert.ok(typeof id2 !== 'undefined' && id2.length === 16, 'passed');
      assert.notDeepEqual(id1, id2, 'passed');
    });
  });
});
