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
// \brief Serpent blockcipher implementation
// Specification can befound here: http://www.cl.cam.ac.uk/~rja14/serpent.html
// There are discussions about the correct output format, because there are NESSIE
// testvectors around. This implementation uses the ORIGINAL Serpent format from the
// AES submission and is fully tested against the AES submission package vectors.
//
// Serpent has a block size of 128 bits and supports a key size of 128, 192 or 256 bits
//
///////////////////////////////////////////////////////////////////////////////

import { Convert, Util, Blockcipher, Streamcipher } from './base';
import { CBC, CTR } from './blockmode';
import { PKCS7 } from './padding';


/**
 * Serpent class
 */
export class Serpent implements Blockcipher {
  blockSize: number;
  key: Uint32Array;
  wMax: number;
  rotW: Function;
  getW: Function;
  setW: Function;
  setWInv: Function;
  keyIt: Function;
  keyLoad: Function;
  keyStore: Function;
  S: Array<Function>;
  SI: Array<Function>;

  /**
   * Serpent ctor
   */
  constructor() {
    this.blockSize = 16;    // Serpent has a fixed block size of 16 bytes
    this.wMax = 0xffffffff;

    this.rotW = function (w: number, n: number) {
      return (w << n | w >>> (32 - n)) & this.wMax;
    };

    this.getW = function (a, i: number) {
      return a[i] | a[i + 1] << 8 | a[i + 2] << 16 | a[i + 3] << 24;
    };

    this.setW = function (a, i: number, w: number) {
      a[i] = w & 0xff; a[i + 1] = (w >>> 8) & 0xff; a[i + 2] = (w >>> 16) & 0xff; a[i + 3] = (w >>> 24) & 0xff;
    };

    this.setWInv = function (a, i: number, w: number) {
      a[i] = (w >>> 24) & 0xff; a[i + 1] = (w >>> 16) & 0xff; a[i + 2] = (w >>> 8) & 0xff; a[i + 3] = w & 0xff;
    };

    this.keyIt = function (a: number, b: number, c: number, d: number, i: number, r) {
      this.key[i] = r[b] = this.rotW(this.key[a] ^ r[b] ^ r[c] ^ r[d] ^ 0x9e3779b9 ^ i, 11);
    };

    this.keyLoad = function (a: number, b: number, c: number, d: number, i: number, r) {
      r[a] = this.key[i]; r[b] = this.key[i + 1]; r[c] = this.key[i + 2]; r[d] = this.key[i + 3];
    };

    this.keyStore = function (a: number, b: number, c: number, d: number, i: number, r) {
      this.key[i] = r[a]; this.key[i + 1] = r[b]; this.key[i + 2] = r[c]; this.key[i + 3] = r[d];
    };

    this.S = [
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x3]; r[x3] |= r[x0]; r[x0] ^= r[x4]; r[x4] ^= r[x2]; r[x4] = ~r[x4]; r[x3] ^= r[x1];
        r[x1] &= r[x0]; r[x1] ^= r[x4]; r[x2] ^= r[x0]; r[x0] ^= r[x3]; r[x4] |= r[x0]; r[x0] ^= r[x2];
        r[x2] &= r[x1]; r[x3] ^= r[x2]; r[x1] = ~r[x1]; r[x2] ^= r[x4]; r[x1] ^= r[x2];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x1]; r[x1] ^= r[x0]; r[x0] ^= r[x3]; r[x3] = ~r[x3]; r[x4] &= r[x1]; r[x0] |= r[x1];
        r[x3] ^= r[x2]; r[x0] ^= r[x3]; r[x1] ^= r[x3]; r[x3] ^= r[x4]; r[x1] |= r[x4]; r[x4] ^= r[x2];
        r[x2] &= r[x0]; r[x2] ^= r[x1]; r[x1] |= r[x0]; r[x0] = ~r[x0]; r[x0] ^= r[x2]; r[x4] ^= r[x1];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x3] = ~r[x3]; r[x1] ^= r[x0]; r[x4]  = r[x0]; r[x0] &= r[x2]; r[x0] ^= r[x3]; r[x3] |= r[x4];
        r[x2] ^= r[x1]; r[x3] ^= r[x1]; r[x1] &= r[x0]; r[x0] ^= r[x2]; r[x2] &= r[x3]; r[x3] |= r[x1];
        r[x0] = ~r[x0]; r[x3] ^= r[x0]; r[x4] ^= r[x0]; r[x0] ^= r[x2]; r[x1] |= r[x2];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x1]; r[x1] ^= r[x3]; r[x3] |= r[x0]; r[x4] &= r[x0]; r[x0] ^= r[x2]; r[x2] ^= r[x1]; r[x1] &= r[x3];
        r[x2] ^= r[x3]; r[x0] |= r[x4]; r[x4] ^= r[x3]; r[x1] ^= r[x0]; r[x0] &= r[x3]; r[x3] &= r[x4];
        r[x3] ^= r[x2]; r[x4] |= r[x1]; r[x2] &= r[x1]; r[x4] ^= r[x3]; r[x0] ^= r[x3]; r[x3] ^= r[x2];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x3]; r[x3] &= r[x0]; r[x0] ^= r[x4]; r[x3] ^= r[x2]; r[x2] |= r[x4]; r[x0] ^= r[x1];
        r[x4] ^= r[x3]; r[x2] |= r[x0]; r[x2] ^= r[x1]; r[x1] &= r[x0]; r[x1] ^= r[x4]; r[x4] &= r[x2];
        r[x2] ^= r[x3]; r[x4] ^= r[x0]; r[x3] |= r[x1]; r[x1] = ~r[x1]; r[x3] ^= r[x0];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x1]; r[x1] |= r[x0]; r[x2] ^= r[x1]; r[x3] = ~r[x3]; r[x4] ^= r[x0]; r[x0] ^= r[x2];
        r[x1] &= r[x4]; r[x4] |= r[x3]; r[x4] ^= r[x0]; r[x0] &= r[x3]; r[x1] ^= r[x3]; r[x3] ^= r[x2];
        r[x0] ^= r[x1]; r[x2] &= r[x4]; r[x1] ^= r[x2]; r[x2] &= r[x0]; r[x3] ^= r[x2];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x1]; r[x3] ^= r[x0]; r[x1] ^= r[x2]; r[x2] ^= r[x0]; r[x0] &= r[x3]; r[x1] |= r[x3];
        r[x4] = ~r[x4]; r[x0] ^= r[x1]; r[x1] ^= r[x2]; r[x3] ^= r[x4]; r[x4] ^= r[x0]; r[x2] &= r[x0];
        r[x4] ^= r[x1]; r[x2] ^= r[x3]; r[x3] &= r[x1]; r[x3] ^= r[x0]; r[x1] ^= r[x2];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x1] = ~r[x1]; r[x4]  = r[x1]; r[x0] = ~r[x0]; r[x1] &= r[x2]; r[x1] ^= r[x3]; r[x3] |= r[x4]; r[x4] ^= r[x2];
        r[x2] ^= r[x3]; r[x3] ^= r[x0]; r[x0] |= r[x1]; r[x2] &= r[x0]; r[x0] ^= r[x4]; r[x4] ^= r[x3];
        r[x3] &= r[x0]; r[x4] ^= r[x1]; r[x2] ^= r[x4]; r[x3] ^= r[x1]; r[x4] |= r[x0]; r[x4] ^= r[x1];
      }
    ];

    this.SI = [
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x3]; r[x1] ^= r[x0]; r[x3] |= r[x1]; r[x4] ^= r[x1]; r[x0] = ~r[x0]; r[x2] ^= r[x3];
        r[x3] ^= r[x0]; r[x0] &= r[x1]; r[x0] ^= r[x2]; r[x2] &= r[x3]; r[x3] ^= r[x4]; r[x2] ^= r[x3];
        r[x1] ^= r[x3]; r[x3] &= r[x0]; r[x1] ^= r[x0]; r[x0] ^= r[x2]; r[x4] ^= r[x3];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x1] ^= r[x3]; r[x4]  = r[x0]; r[x0] ^= r[x2]; r[x2] = ~r[x2]; r[x4] |= r[x1]; r[x4] ^= r[x3];
        r[x3] &= r[x1]; r[x1] ^= r[x2]; r[x2] &= r[x4]; r[x4] ^= r[x1]; r[x1] |= r[x3]; r[x3] ^= r[x0];
        r[x2] ^= r[x0]; r[x0] |= r[x4]; r[x2] ^= r[x4]; r[x1] ^= r[x0]; r[x4] ^= r[x1];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x2] ^= r[x1]; r[x4]  = r[x3]; r[x3] = ~r[x3]; r[x3] |= r[x2]; r[x2] ^= r[x4]; r[x4] ^= r[x0];
        r[x3] ^= r[x1]; r[x1] |= r[x2]; r[x2] ^= r[x0]; r[x1] ^= r[x4]; r[x4] |= r[x3]; r[x2] ^= r[x3];
        r[x4] ^= r[x2]; r[x2] &= r[x1]; r[x2] ^= r[x3]; r[x3] ^= r[x4]; r[x4] ^= r[x0];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x2] ^= r[x1]; r[x4]  = r[x1]; r[x1] &= r[x2]; r[x1] ^= r[x0]; r[x0] |= r[x4]; r[x4] ^= r[x3];
        r[x0] ^= r[x3]; r[x3] |= r[x1]; r[x1] ^= r[x2]; r[x1] ^= r[x3]; r[x0] ^= r[x2]; r[x2] ^= r[x3];
        r[x3] &= r[x1]; r[x1] ^= r[x0]; r[x0] &= r[x2]; r[x4] ^= r[x3]; r[x3] ^= r[x0]; r[x0] ^= r[x1];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x2] ^= r[x3]; r[x4]  = r[x0]; r[x0] &= r[x1]; r[x0] ^= r[x2]; r[x2] |= r[x3]; r[x4] = ~r[x4];
        r[x1] ^= r[x0]; r[x0] ^= r[x2]; r[x2] &= r[x4]; r[x2] ^= r[x0]; r[x0] |= r[x4]; r[x0] ^= r[x3];
        r[x3] &= r[x2]; r[x4] ^= r[x3]; r[x3] ^= r[x1]; r[x1] &= r[x0]; r[x4] ^= r[x1]; r[x0] ^= r[x3];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  =  r[x1]; r[x1] |= r[x2]; r[x2] ^= r[x4]; r[x1] ^= r[x3]; r[x3] &= r[x4]; r[x2] ^= r[x3]; r[x3] |= r[x0];
        r[x0]  = ~r[x0]; r[x3] ^= r[x2]; r[x2] |= r[x0]; r[x4] ^= r[x1]; r[x2] ^= r[x4]; r[x4] &= r[x0]; r[x0] ^= r[x1];
        r[x1] ^=  r[x3]; r[x0] &= r[x2]; r[x2] ^= r[x3]; r[x0] ^= r[x2]; r[x2] ^= r[x4]; r[x4] ^= r[x3];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x0] ^= r[x2]; r[x4]  = r[x0]; r[x0] &= r[x3]; r[x2] ^= r[x3]; r[x0] ^= r[x2]; r[x3] ^= r[x1];
        r[x2] |= r[x4]; r[x2] ^= r[x3]; r[x3] &= r[x0]; r[x0] = ~r[x0]; r[x3] ^= r[x1]; r[x1] &= r[x2];
        r[x4] ^= r[x0]; r[x3] ^= r[x4]; r[x4] ^= r[x2]; r[x0] ^= r[x1]; r[x2] ^= r[x0];
      },
      function (r, x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x3]; r[x3] &= r[x0]; r[x0] ^= r[x2]; r[x2] |= r[x4]; r[x4] ^= r[x1]; r[x0] = ~r[x0]; r[x1] |= r[x3];
        r[x4] ^= r[x0]; r[x0] &= r[x2]; r[x0] ^= r[x1]; r[x1] &= r[x2]; r[x3] ^= r[x2]; r[x4] ^= r[x3];
        r[x2] &= r[x3]; r[x3] |= r[x0]; r[x1] ^= r[x4]; r[x3] ^= r[x4]; r[x4] &= r[x0]; r[x4] ^= r[x2];
      }
    ];
  };


  /**
   * Init the cipher, private function
   * @param {Uint8Array} key The key. The key size can be 128, 192 or 256 bits
   */
  private init(key: Uint8Array) {
    let i, j, m, n, len;
    const KC = new Uint32Array([7788, 63716, 84032, 7891, 78949, 25146, 28835, 67288, 84032, 40055, 7361, 1940, 77639, 27525, 24193, 75702,
                                7361, 35413, 83150, 82383, 58619, 48468, 18242, 66861, 83150, 69667, 7788, 31552, 40054, 23222, 52496, 57565, 7788, 63716]);

    this.key = new Uint32Array(132);
    this.key[key.length] = 1;
    // reverse
    for (i = 0, len = key.length; i < len; i++) {
      this.key[i] = key[len - i - 1];
    }

    for (i = 0; i < 8; i++) {
      this.key[i] = (this.key[4 * i] & 0xff) | (this.key[4 * i + 1] & 0xff) << 8 | (this.key[4 * i + 2] & 0xff) << 16 | (this.key[4 * i + 3] & 0xff) << 24;
    }

    let r = [this.key[3], this.key[4], this.key[5], this.key[6], this.key[7]];

    i = 0; j = 0;
    while (this.keyIt(j++, 0, 4, 2, i++, r), this.keyIt(j++, 1, 0, 3, i++, r), i < 132) {
      this.keyIt(j++, 2, 1, 4, i++, r);
      if (i === 8) {
        j = 0;
      }
      this.keyIt(j++, 3, 2, 0, i++, r);
      this.keyIt(j++, 4, 3, 1, i++, r);
    }

    i = 128; j = 3; n = 0;
    while (m = KC[n++], this.S[j++ % 8](r, m % 5, m % 7, m % 11, m % 13, m % 17), m = KC[n], this.keyStore(m % 5, m % 7, m % 11, m % 13, i, r), i > 0) {
      i -= 4;
      this.keyLoad(m % 5, m % 7, m % 11, m % 13, i, r);
    }
  }


  private K(r: any, a: number, b: number, c: number, d: number, i: number) {
    r[a] ^= this.key[4 * i];
    r[b] ^= this.key[4 * i + 1];
    r[c] ^= this.key[4 * i + 2];
    r[d] ^= this.key[4 * i + 3];
  };


  private LK(r: any, a: number, b: number, c: number, d: number, e: number, i: number) {
    r[a]  = this.rotW(r[a], 13);
    r[c]  = this.rotW(r[c], 3);
    r[b] ^= r[a];
    r[e]  = (r[a] << 3) & this.wMax;
    r[d] ^= r[c];
    r[b] ^= r[c];
    r[b]  = this.rotW(r[b], 1);
    r[d] ^= r[e];
    r[d]  = this.rotW(r[d], 7);
    r[e]  = r[b];
    r[a] ^= r[b];
    r[e]  = (r[e] << 7) & this.wMax;
    r[c] ^= r[d];
    r[a] ^= r[d];
    r[c] ^= r[e];
    r[d] ^= this.key[4 * i + 3];
    r[b] ^= this.key[4 * i + 1];
    r[a]  = this.rotW(r[a], 5);
    r[c]  = this.rotW(r[c], 22);
    r[a] ^= this.key[4 * i + 0];
    r[c] ^= this.key[4 * i + 2];
  };


  private KL(r: any, a: number, b: number, c: number, d: number, e: number, i: number) {
    r[a] ^= this.key[4 * i + 0];
    r[b] ^= this.key[4 * i + 1];
    r[c] ^= this.key[4 * i + 2];
    r[d] ^= this.key[4 * i + 3];
    r[a]  = this.rotW(r[a], 27);
    r[c]  = this.rotW(r[c], 10);
    r[e]  = r[b];
    r[c] ^= r[d];
    r[a] ^= r[d];
    r[e]  = (r[e] << 7) & this.wMax;
    r[a] ^= r[b];
    r[b]  = this.rotW(r[b], 31);
    r[c] ^= r[e];
    r[d]  = this.rotW(r[d], 25);
    r[e]  = (r[a] << 3) & this.wMax;
    r[b] ^= r[a];
    r[d] ^= r[e];
    r[a]  = this.rotW(r[a], 19);
    r[b] ^= r[c];
    r[d] ^= r[c];
    r[c]  = this.rotW(r[c], 29);
  };


  /**
   * Serpent block encryption
   * @param {Uint8Array} key Key
   * @param {Uint8Array} pt The plaintext
   * @return {Uint8Array} Ciphertext
   */
  encrypt(key: Uint8Array, pt: Uint8Array): Uint8Array {
    this.init(key);

    const EC = new Uint32Array([44255, 61867, 45034, 52496, 73087, 56255, 43827, 41448, 18242, 1939, 18581, 56255, 64584, 31097, 26469,
                                77728, 77639, 4216, 64585, 31097, 66861, 78949, 58006, 59943, 49676, 78950, 5512, 78949, 27525, 52496, 18670, 76143]);

    let blk = new Uint8Array(pt.length);
    // reverse
    for (let i = 0, len = pt.length; i < len; i++) {
      blk[i] = pt[len - i - 1];
    }
    let r = [this.getW(blk, 0), this.getW(blk, 4), this.getW(blk, 8), this.getW(blk, 12)];

    this.K(r, 0, 1, 2, 3, 0);
    let n = 0, m = EC[0];
    while (this.S[n % 8](r, m % 5, m % 7, m % 11, m % 13, m % 17), n < 31) {
      m = EC[++n];
      this.LK(r, m % 5, m % 7, m % 11, m % 13, m % 17, n);
    }
    this.K(r, 0, 1, 2, 3, 32);

    let ct = new Uint8Array(pt.length);
    this.setWInv(ct, 0, r[3]); this.setWInv(ct, 4, r[2]); this.setWInv(ct, 8, r[1]); this.setWInv(ct, 12, r[0]);

    return ct;
  }


  /**
   * Serpent block decryption
   * @param {Uint8Array} key Key
   * @param {Uint8Array} ct The ciphertext
   * @return {Uint8Array} Plaintext
   */
  decrypt(key: Uint8Array, ct: Uint8Array): Uint8Array {
    this.init(key);

    const DC = new Uint32Array([44255, 60896, 28835, 1837, 1057, 4216, 18242, 77301, 47399, 53992, 1939, 1940, 66420, 39172, 78950,
                                45917, 82383, 7450, 67288, 26469, 83149, 57565, 66419, 47400, 58006, 44254, 18581, 18228, 33048, 45034, 66508, 7449]);

    let blk = new Uint8Array(ct.length);
    // reverse
    for (let i = 0, len = ct.length; i < len; i++) {
      blk[i] = ct[len - i - 1];
    }
    let r = [this.getW(blk, 0), this.getW(blk, 4), this.getW(blk, 8), this.getW(blk, 12)];

    this.K(r, 0, 1, 2, 3, 32);
    let n = 0, m = DC[0];
    while (this.SI[7 - n % 8](r, m % 5, m % 7, m % 11, m % 13, m % 17), n < 31) {
      m = DC[++n];
      this.KL(r, m % 5, m % 7, m % 11, m % 13, m % 17, 32 - n);
    }
    this.K(r, 2, 3, 1, 4, 0);

    let pt = new Uint8Array(ct.length);
    this.setWInv(pt, 0, r[4]); this.setWInv(pt, 4, r[1]); this.setWInv(pt, 8, r[3]); this.setWInv(pt, 12, r[2]);

    return pt;
  }


  /**
   * Performs a quick selftest
   * @return {Boolean} True if successful
   */
  selftest(): boolean {
    const tv_CBC_PKCS7 = [
      {
        key: '06a9214036b8a15b512e03d534120006',
        iv: '3dafba429d9eb430b422da802c9fac41',
        pt: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        ct: '714373e9991e8a58f79efa62b46f7652fbfa5de596b93acaafbdb2412311ac13e365c4170a4166dd1b95cfde3a21f6b2'
      },
      {
        key: '0x6c3ea0477630ce21a2ce334aa746c2cd',
        iv: '0xc782dc4c098c66cbd9cd27d825682c81',
        pt: 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf',
        ct: '90d0d1d8340ef5e8b9922f3c173ea1066632c5fec470be3935b5bfaeef033a0dd50a459d5c70fc8417540ae43cc507339b0085a268528f2d1de93cf65e96037685ebf5a6bcc81b70f132aba9b782ea99'
      }
    ];

    let aes = new Serpent();
    let res = true;
/*
    for (let i = 0; i < tv_CBC_PKCS7.length; i++) {
      let key = Convert.hex2bin(tv_CBC_PKCS7[i].key);
      let pt = Convert.hex2bin(tv_CBC_PKCS7[i].pt);
      let ct = Convert.hex2bin(tv_CBC_PKCS7[i].ct);
      let iv = Convert.hex2bin(tv_CBC_PKCS7[i].iv);
      let ct2 = aes.encrypt(key, pt, iv);
      res = res && Util.compare(ct2, ct);
      let pt2 = aes.decrypt(key, ct, iv);
      res = res && Util.compare(pt2, pt);
    }
*/
    return res;
  }

}

///////////////////////////////////////////////////////////////////////////////


export class Serpent_CBC implements Streamcipher {
  cipher: Serpent;
  blockmode: CBC;

  constructor() {
    this.cipher    = new Serpent();
    this.blockmode = new CBC(this.cipher);
  }

  encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.blockmode.encrypt(key, pt, iv);
  }

  decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.blockmode.decrypt(key, ct, iv);
  }

  selftest(): boolean {
    return this.cipher.selftest();
  }
}


export class Serpent_CTR implements Streamcipher {
  cipher: Serpent;
  blockmode: CTR;

  constructor() {
    this.cipher    = new Serpent();
    this.blockmode = new CTR(this.cipher);
  }

  encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.blockmode.encrypt(key, pt, iv);
  }

  decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.blockmode.decrypt(key, ct, iv);
  }

  selftest(): boolean {
    return this.cipher.selftest();
  }
}


export class Serpent_CBC_PKCS7 implements Streamcipher {
  cipher: Serpent_CBC;
  padding: PKCS7;

  constructor() {
    this.cipher  = new Serpent_CBC();
    this.padding = new PKCS7();
  }

  encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.cipher.encrypt(key, this.padding.pad(pt, this.cipher.cipher.blockSize), iv);
  }

  decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.padding.strip(this.cipher.decrypt(key, ct, iv));
  }

  selftest(): boolean {
    return this.cipher.selftest();
  }
}


export class Serpent_CTR_PKCS7 implements Streamcipher {
  cipher: Serpent_CTR;
  padding: PKCS7;

  constructor() {
    this.cipher  = new Serpent_CTR();
    this.padding = new PKCS7();
  }

  encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.cipher.encrypt(key, this.padding.pad(pt, this.cipher.cipher.blockSize), iv);
  }

  decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.padding.strip(this.cipher.decrypt(key, ct, iv));
  }

  selftest(): boolean {
    return this.cipher.selftest();
  }
}
