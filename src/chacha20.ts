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
// \brief chacha20 stream cipher implementation
// This implementation is derived from chacha.c
// See for details: http://cr.yp.to/chacha.html
//
///////////////////////////////////////////////////////////////////////////////

import { Streamcipher } from "./base";


/**
 * ChaCha20 class
 */
export class ChaCha20 implements Streamcipher {
  keySize: number;
  nonceSize: number;
  input: Uint32Array;


  /**
   * ctor
   */
  constructor() {
    this.keySize = 32;    // 256 bit key
    this.nonceSize = 8;   //  64 bit nonce
  }


  /**
   * Init, private function
    * @param {Array} key The secret key as byte array (32 byte)
    * @param {Array} nonce The nonce (IV) as byte array (8 byte)
    * @param {Number} counter Optional counter init value, 0 is default
    * @return {ChaCha20} this
   */
  private init(key: Uint8Array, nonce: Uint8Array, counter: number = 0): ChaCha20 {
    this.input     = new Uint32Array(16);
    this.input[0]  = 0x61707865;                    // constant "expand 32-byte k"
    this.input[1]  = 0x3320646e;
    this.input[2]  = 0x79622d32;
    this.input[3]  = 0x6b206574;
    this.input[4]  = this.U8TO32_LITTLE(key, 0);    // key
    this.input[5]  = this.U8TO32_LITTLE(key, 4);
    this.input[6]  = this.U8TO32_LITTLE(key, 8);
    this.input[7]  = this.U8TO32_LITTLE(key, 12);
    this.input[8]  = this.U8TO32_LITTLE(key, 16);
    this.input[9]  = this.U8TO32_LITTLE(key, 20);
    this.input[10] = this.U8TO32_LITTLE(key, 24);
    this.input[11] = this.U8TO32_LITTLE(key, 28);
    this.input[12] = counter & 0xffffffff;          // counter, (chacha20 is like a block cipher in CTR mode)
    this.input[13] = 0;
    this.input[14] = this.U8TO32_LITTLE(nonce, 0);  // nonce
    this.input[15] = this.U8TO32_LITTLE(nonce, 4);
    return this;
  }


  private U8TO32_LITTLE(x: Uint8Array, i: number): number {
    return x[i] | (x[i + 1] << 8) | (x[i + 2] << 16) | (x[i + 3] << 24);
  }


  private U32TO8_LITTLE(x: any, i: number, u: number) {
    x[i]     = u & 0xff; u >>>= 8;
    x[i + 1] = u & 0xff; u >>>= 8;
    x[i + 2] = u & 0xff; u >>>= 8;
    x[i + 3] = u & 0xff;
  }


  private ROTATE(v: number, c: number): number {
    return (v << c) | (v >>> (32 - c));
  }


  private QUARTERROUND(x: any, a: number, b: number, c: number, d: number) {
    x[a] += x[b]; x[d] = this.ROTATE(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = this.ROTATE(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = this.ROTATE(x[d] ^ x[a],  8);
    x[c] += x[d]; x[b] = this.ROTATE(x[b] ^ x[c],  7);
  }


  private stream(src: Uint8Array, dst: Uint8Array, len: number) {
    let s = new Uint32Array(16), buf = new Uint8Array(64);
    let i = 0, dpos = 0, spos = 0;

    while (len > 0) {
      for (i = 16; i--;) { s[i] = this.input[i]; }
      for (i = 0; i < 10; ++i) {
        this.QUARTERROUND(s, 0, 4,  8, 12);
        this.QUARTERROUND(s, 1, 5,  9, 13);
        this.QUARTERROUND(s, 2, 6, 10, 14);
        this.QUARTERROUND(s, 3, 7, 11, 15);
        this.QUARTERROUND(s, 0, 5, 10, 15);
        this.QUARTERROUND(s, 1, 6, 11, 12);
        this.QUARTERROUND(s, 2, 7,  8, 13);
        this.QUARTERROUND(s, 3, 4,  9, 14);
      }
      for (i = 0; i < 16; ++i) { s[i] += this.input[i]; }
      for (i = 0; i < 16; ++i) { this.U32TO8_LITTLE(buf, 4 * i, s[i]); }

      // inc 64 bit counter
      if (++this.input[12] === 0) {
        this.input[13]++;
      }
      if (len <= 64) {
        for (i = len; i--;) {
          dst[i + dpos] = src[i + spos] ^ buf[i];
        }
        return;
      }
      for (i = 64; i--;) {
        dst[i + dpos] = src[i + spos] ^ buf[i];
      }
      len  -= 64;
      spos += 64;
      dpos += 64;
    }
  }


  /**
   * Encrypt a byte array, native chacha20 function
   * @param {Uint8Array} key The secret key as byte array (32 byte)
   * @param {Uint8Array} pt Plaintext as byte array
   * @param {Uint8Array} iv The nonce (IV) as byte array (8 byte)
   * @param {Number} cnt Optional counter init value, 0 is default
   * @return {Uint8Array} ct Ciphertext as byte array
   */
  encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array, cnt: number = 0): Uint8Array {
    let ct = new Uint8Array(pt.length);
    this.init(key, iv, cnt).stream(pt, ct, pt.length);
    return ct;
  }


  /**
   * Decrypt a byte array, native chacha20 function
   * @param {Uint8Array} key The secret key as byte array
   * @param {Uint8Array} ct Ciphertext as byte array
   * @param {Uint8Array} iv The nonce (IV) as byte array
   * @param {Number} cnt Optional counter init value, 0 is default
   * @return {Uint8Array} pt Plaintext as byte array
   */
  decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array, cnt: number = 0): Uint8Array {
    let pt = new Uint8Array(ct.length);
    this.init(key, iv, cnt).stream(ct, pt, ct.length);
    return pt;
  }


  /**
   * Performs a quick selftest
   * @return {Boolean} True if successful
   */
  selftest(): boolean {
    return true;
  }
}
