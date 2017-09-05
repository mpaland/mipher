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
// \brief SHA1 implementation
//        Generates a 20 byte (160 bit) hash value
//        CAUTION: SHA1 is meant to be broken, consider using a more secure hash
//                 like SHA512 or better SHA3
//
///////////////////////////////////////////////////////////////////////////////

import { Convert, Util, Hash } from "./base";


/**
 * SHA1 class
 */
export class SHA1 implements Hash {
  hashSize: number;
  buffer: Uint8Array;
  bufferIndex: number;
  count: Uint32Array;
  K: Uint32Array;
  H: Uint32Array;
  S: Function;
  F: Function;

  /**
   * SHA1 ctor
   */
  constructor() {
    this.hashSize = 20;
    this.buffer = new Uint8Array(64);
    this.K = new Uint32Array([0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]);

    // circular left-shift operator
    this.S = function (n, x) { return (x << n) | (x >>> 32 - n); };

    this.F = function (t, b, c, d) {
      if (t <= 19) {
        return (b & c) | (~b & d);
      } else if (t <= 39) {
        return b ^ c ^ d;
      } else if (t <= 59) {
        return (b & c) | (b & d) | (c & d);
      } else if (t <= 79) {
        return b ^ c ^ d;
      }
    };

    this.init();
  }


  /**
   * Init the hash
   * @return {SHA1} this
   */
  init(): SHA1 {
    this.H = new Uint32Array([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
    this.bufferIndex = 0;
    this.count = new Uint32Array(2);
    return this;
  }


  /**
   * Perform one transformation cycle
   */
  private transform() {
    let h = this.H,
      a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

    // convert byte buffer to words
    let w = new Uint32Array(80);
    for (let i = 0; i < 16; i++) {
      w[i] = (this.buffer[(i << 2) + 3]) | (this.buffer[(i << 2) + 2] << 8) | (this.buffer[(i << 2) + 1] << 16) | (this.buffer[i << 2] << 24);
    }

    for (let t = 0; t < 80; t++) {
      if (t >= 16) {
        w[t] = this.S(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]);
      }
      let tmp = (this.S(5, a) + this.F(t, b, c, d) + e + w[t] + this.K[Math.floor(t / 20)]) | 0;
      e = d;
      d = c;
      c = this.S(30, b);
      b = a;
      a = tmp;
    }

    h[0] = (h[0] + a) | 0;
    h[1] = (h[1] + b) | 0;
    h[2] = (h[2] + c) | 0;
    h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0;
  }


  /**
   * Update the hash with additional message data
   * @param {Uint8Array} msg Additional message data as byte array
   * @return {SHA1} this
   */
  update(msg?: Uint8Array): SHA1 {
    msg = msg || new Uint8Array(0);
    // process the msg as many times as possible, the rest is stored in the buffer
    // message is processed in 512 bit (64 byte chunks)
    for (let i = 0; i < msg.length; i++) {
      this.buffer[this.bufferIndex++] = msg[i];
      if (this.bufferIndex === 64) {
        this.transform();
        this.bufferIndex = 0;
      }
    }

    // counter update (number of message bits)
    let c = this.count;
    if ((c[0] += (msg.length << 3)) < (msg.length << 3)) {
      c[1]++;
    }
    c[1] += (msg.length >>> 29);

    return this;
  }


  /**
   * Finalize the hash with additional message data
   * @param {Uint8Array} msg Additional message data as byte array
   * @return {Uint8Array} Hash as 20 byte array
   */
  digest(msg?: Uint8Array): Uint8Array {
    this.update(msg);

    // append '1'
    let b = this.buffer, idx = this.bufferIndex;
    b[idx++] = 0x80;

    // zeropad up to byte pos 56
    while (idx !== 56) {
      if (idx === 64) {
        this.transform();
        idx = 0;
      }
      b[idx++] = 0;
    }

    // append length in bits
    let c = this.count;
    b[56] = (c[1] >>> 24) & 0xff;
    b[57] = (c[1] >>> 16) & 0xff;
    b[58] = (c[1] >>>  8) & 0xff;
    b[59] = (c[1] >>>  0) & 0xff;
    b[60] = (c[0] >>> 24) & 0xff;
    b[61] = (c[0] >>> 16) & 0xff;
    b[62] = (c[0] >>>  8) & 0xff;
    b[63] = (c[0] >>>  0) & 0xff;
    this.transform();

    // return the hash as byte array (20 bytes)
    let hash = new Uint8Array(20);
    for (let i = 0; i < 5; i++) {
      hash[(i << 2) + 0] = (this.H[i] >>> 24) & 0xff;
      hash[(i << 2) + 1] = (this.H[i] >>> 16) & 0xff;
      hash[(i << 2) + 2] = (this.H[i] >>>  8) & 0xff;
      hash[(i << 2) + 3] = (this.H[i] >>>  0) & 0xff;
    }

    // clear internal states and prepare for new hash
    this.init();

    return hash;
  }


  /**
   * All in one step
   * @param {Uint8Array} msg Additional message data
   * @return {Uint8Array} Hash as 20 byte array
   */
  hash(msg?: Uint8Array): Uint8Array {
    return this.init().digest(msg);
  }

  /**
   * Performs a quick selftest
   * @return {Boolean} True if successful
   */
  selftest(): boolean {
    let cumulative = new SHA1(), sha = new SHA1();
    let toBeHashed = '', hash;
    for (let i = 0; i < 10; i++) {
      for (let n = 100 * i; n < 100 * (i + 1); n++) {
        hash = Convert.bin2hex(sha.hash(Convert.str2bin(toBeHashed)));
        cumulative.update(Convert.str2bin(hash));
        toBeHashed = (hash.substring(0, 2) + toBeHashed).substring(0, n + 1);
      }
    }
    hash = Convert.bin2hex(cumulative.digest());
    return hash === '00665a042bac62281f2f3666c3565dd005d364dc';
  }
}
