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
// \brief SHA256 implementation
//        Generates a 32 byte hash value
//
///////////////////////////////////////////////////////////////////////////////

import { Convert, Util, Hash } from './base';


/**
 * SHA256 class
 */
export class SHA256 implements Hash {
  hashSize: number;
  buffer: Uint8Array;
  bufferIndex: number;
  count: Uint32Array;
  K: Uint32Array;
  H: Uint32Array;


  /**
   * SHA256 ctor
   */
  constructor() {
    this.hashSize = 32;
    this.buffer = new Uint8Array(64);
    this.K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);
    this.init();
  }


  /**
   * Init the hash
   * @return {SHA256} this
   */
  init(): SHA256 {
    this.H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    this.bufferIndex = 0;
    this.count = new Uint32Array(2);
    this.count[0] = this.count[1] = 0;
    Util.clear(this.buffer);

    return this;
  }


  /**
   * Perform one transformation cycle
   */
  private transform() {
    let h = this.H,
        h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4], h5 = h[5], h6 = h[6], h7 = h[7];

    // convert byte buffer to uint32
    let w = new Uint32Array(16), i;
    for (i = 15; i >= 0; i--) {
      w[i] = (this.buffer[(i << 2) + 3]) | (this.buffer[(i << 2) + 2] << 8) | (this.buffer[(i << 2) + 1] << 16) | (this.buffer[i << 2] << 24);
    }

    for (i = 0; i < 64; i++) {
      let tmp;
      if (i < 16) {
        tmp = w[i];
      }
      else {
        let a = w[(i + 1) & 15];
        let b = w[(i + 14) & 15];
        tmp = w[i & 15] = ((a >>> 7 ^ a >>> 18 ^ a >>> 3 ^ a << 25 ^ a << 14) + (b >>> 17 ^ b >>> 19 ^ b >>> 10 ^ b << 15 ^ b << 13) + w[i & 15] + w[(i + 9) & 15]) | 0;
      }
      tmp = (tmp + h7 + (h4 >>> 6 ^ h4 >>> 11 ^ h4 >>> 25 ^ h4 << 26 ^ h4 << 21 ^ h4 << 7) + (h6 ^ h4 & (h5 ^ h6)) + this.K[i]) | 0;

      h7 = h6;
      h6 = h5;
      h5 = h4;
      h4 = h3 + tmp;
      h3 = h2;
      h2 = h1;
      h1 = h0;
      h0 = (tmp + ((h1 & h2) ^ (h3 & (h1 ^ h2))) + (h1 >>> 2 ^ h1 >>> 13 ^ h1 >>> 22 ^ h1 << 30 ^ h1 << 19 ^ h1 << 10)) | 0;
    }

    h[0] = (h[0] + h0) | 0;
    h[1] = (h[1] + h1) | 0;
    h[2] = (h[2] + h2) | 0;
    h[3] = (h[3] + h3) | 0;
    h[4] = (h[4] + h4) | 0;
    h[5] = (h[5] + h5) | 0;
    h[6] = (h[6] + h6) | 0;
    h[7] = (h[7] + h7) | 0;
  }


  /**
   * Update the hash with additional message data
   * @param {Array} msg Additional message data as byte array
   * @return {SHA256} this
   */
  update(msg?: Uint8Array): SHA256 {
    msg = msg || new Uint8Array(0);
    // process the msg as many times as possible, the rest is stored in the buffer
    // message is processed in 512 bit (64 byte chunks)
    for (let i = 0, len = msg.length; i < len; i++) {
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
   * @return {Uint8Array} Hash as 32 byte array
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

    // return the hash as byte array
    let hash = new Uint8Array(32), i;
    for (i = 0; i < 8; i++) {
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
   * @param {Uint8Array} msg Message data as byte array
   * @return {Uint8Array} Hash as 32 byte array
   */
  hash(msg?: Uint8Array): Uint8Array {
    return this.init().digest(msg);
  }


  /**
   * Performs a quick selftest
   * @return {Boolean} True if successful
   */
  selftest(): boolean {
    let cumulative = new SHA256(), sha = new SHA256();
    let toBeHashed = '', hash, i, n;
    for (i = 0; i < 10; i++) {
      for (n = 100 * i; n < 100 * (i + 1); n++) {
        hash = Convert.bin2hex(sha.hash(Convert.str2bin(toBeHashed)));
        cumulative.update(Convert.str2bin(hash));
        toBeHashed = (hash.substring(0, 2) + toBeHashed).substring(0, n + 1);
      }
    }
    hash = Convert.bin2hex(cumulative.digest());
    return hash === 'f305c76d5d457ddf04f1927166f5e13429407049a5c5f29021916321fcdcd8b4';
  }
}
