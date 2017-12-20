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
// \brief PBKDF2 implementation
//        Password-Based Key Derivation Function 2, takes a hash/HMAC function and
//        generates a derived, streched password key due to iteration rounds.
//        At least a minimum of 10000 rounds are recommended!
//
///////////////////////////////////////////////////////////////////////////////

import { Convert, Util, KeyedHash } from './base';
import { SHA256 } from './sha256';
import { HMAC } from './hmac';


/**
 * PBKDF2 class
 */
export class PBKDF2 {

  /**
   * ctor
   * @param {KeyedHash} hmac HMAC function like HMAC-SHA1 or HMAC-SHA256
   * @param {Number} rounds Optional, number of iterations, defaults to 10000
   */
  constructor(private hmac: KeyedHash, private rounds: number = 10000) {
  }


  /**
   * Generate derived key
   * @param {Uint8Array} password The password
   * @param {Uint8Array} salt The salt
   * @param {Number} length Optional, the derived key length (dkLen), defaults to the half of the HMAC block size
   * @return {Uint8Array} The derived key as byte array
   */
  hash(password: Uint8Array, salt: Uint8Array, length?: number): Uint8Array {
    let u, ui; length = length || (this.hmac.hashSize >>> 1);
    let out = new Uint8Array(length);
    for (let k = 1, len = Math.ceil(length / this.hmac.hashSize); k <= len; k++) {
      u = ui = this.hmac.init(password).update(salt).digest(new Uint8Array([(k >>> 24) & 0xFF, (k >>> 16) & 0xFF, (k >>> 8) & 0xFF, k & 0xFF]));
      for (let i = 1; i < this.rounds; i++) {
        ui = this.hmac.hash(password, ui);
        for (let j = 0; j < ui.length; j++) {
          u[j] ^= ui[j];
        }
      }
      // append data
      out.set(u.subarray(0, k * this.hmac.hashSize < length ? this.hmac.hashSize : length - (k - 1) * this.hmac.hashSize), (k - 1) * this.hmac.hashSize);
    }
    return out;
  }


  /**
   * Performs a quick selftest
   * @return {Boolean} True if successful
   */
  selftest(): boolean {
    const tv = {
      key:    'password',
      salt:   'salt',
      c:      2,
      sha256: 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43'
    };

    let pbkdf2_sha256 = new PBKDF2(new HMAC(new SHA256()), tv.c);
    let key = Convert.str2bin(tv.key);
    let salt = Convert.str2bin(tv.salt);
    let mac = pbkdf2_sha256.hash(key, salt, Convert.hex2bin(tv.sha256).length);
    return Convert.bin2hex(mac) === tv.sha256;
  }
}
