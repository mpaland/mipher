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
// \brief SHA512 implementation
//        Generates a 64 byte (512 bit) hash value
//
///////////////////////////////////////////////////////////////////////////////

import {Convert, Util, Hash} from "./base";


/**
 * SHA512 class
 */
export class SHA512 implements Hash {
  hashSize: number;
  buffer: Uint8Array;
  bufferIndex: number;
  count: Uint32Array;
  K: Uint32Array;
  H: Uint32Array;


  /**
   * SHA512 ctor
   */
  constructor() {
    this.hashSize = 64;
    this.buffer = new Uint8Array(128); // 128 byte array
    this.K = new Uint32Array(
      [0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
       0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
       0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
       0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
       0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
       0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
       0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
       0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
       0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
       0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
       0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
       0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
       0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
       0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
       0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
       0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
       0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
       0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
       0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
       0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817]);
    this.init();
  }


  /**
   * Init the hash
   * @return {Object} this
   */
  init(): SHA512 {
    this.H = new Uint32Array([0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
                              0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179]);
    this.bufferIndex = 0;
    this.count = new Uint32Array(2);

    return this;
  }


  /**
   * Perform one transformation cycle
   */
  private transform() {
    let h = this.H,
      h0h = h[0], h0l = h[1], h1h = h[2], h1l = h[3],
      h2h = h[4], h2l = h[5], h3h = h[6], h3l = h[7],
      h4h = h[8], h4l = h[9], h5h = h[10], h5l = h[11],
      h6h = h[12], h6l = h[13], h7h = h[14], h7l = h[15];

    let ah = h0h, al = h0l, bh = h1h, bl = h1l,
        ch = h2h, cl = h2l, dh = h3h, dl = h3l,
        eh = h4h, el = h4l, fh = h5h, fl = h5l,
        gh = h6h, gl = h6l, hh = h7h, hl = h7l;

    // convert byte buffer to 32 bit
    let w = new Uint32Array(160), i;
    for (i = 31; i >= 0; i--) {
      w[i] = (this.buffer[(i << 2) + 3]) | (this.buffer[(i << 2) + 2] << 8) | (this.buffer[(i << 2) + 1] << 16) | (this.buffer[i << 2] << 24);
    }

    for (i = 0; i < 80; i++) {
      let wrh, wrl;
      if (i < 16) {
        wrh = w[i * 2];
        wrl = w[i * 2 + 1];
      } else {
        // Gamma0
        let gamma0xh = w[(i - 15) * 2];
        let gamma0xl = w[(i - 15) * 2 + 1];
        let gamma0h =
          ((gamma0xl << 31) | (gamma0xh >>> 1)) ^
          ((gamma0xl << 24) | (gamma0xh >>> 8)) ^
          ((gamma0xh >>> 7));
        let gamma0l =
          ((gamma0xh << 31) | (gamma0xl >>> 1)) ^
          ((gamma0xh << 24) | (gamma0xl >>> 8)) ^
          ((gamma0xh << 25) | (gamma0xl >>> 7));

        // Gamma1
        let gamma1xh = w[(i - 2) * 2];
        let gamma1xl = w[(i - 2) * 2 + 1];
        let gamma1h =
          ((gamma1xl << 13) | (gamma1xh >>> 19)) ^
          ((gamma1xh << 3) | (gamma1xl >>> 29)) ^
          ((gamma1xh >>> 6));
        let gamma1l =
          ((gamma1xh << 13) | (gamma1xl >>> 19)) ^
          ((gamma1xl << 3) | (gamma1xh >>> 29)) ^
          ((gamma1xh << 26) | (gamma1xl >>> 6));

        // shortcuts
        let wr7h  = w[(i - 7) * 2],
            wr7l  = w[(i - 7) * 2 + 1],
            wr16h = w[(i - 16) * 2],
            wr16l = w[(i - 16) * 2 + 1];

        // W(round) = gamma0 + W(round - 7) + gamma1 + W(round - 16)
        wrl = gamma0l + wr7l;
        wrh = gamma0h + wr7h + ((wrl >>> 0) < (gamma0l >>> 0) ? 1 : 0);
        wrl += gamma1l;
        wrh += gamma1h + ((wrl >>> 0) < (gamma1l >>> 0) ? 1 : 0);
        wrl += wr16l;
        wrh += wr16h + ((wrl >>> 0) < (wr16l >>> 0) ? 1 : 0);
      }

      w[i * 2] = wrh |= 0;
      w[i * 2 + 1] = wrl |= 0;

      // Ch
      let chh = (eh & fh) ^ (~eh & gh);
      let chl = (el & fl) ^ (~el & gl);

      // Maj
      let majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
      let majl = (al & bl) ^ (al & cl) ^ (bl & cl);

      // Sigma0
      let sigma0h = ((al << 4) | (ah >>> 28)) ^ ((ah << 30) | (al >>> 2)) ^ ((ah << 25) | (al >>> 7));
      let sigma0l = ((ah << 4) | (al >>> 28)) ^ ((al << 30) | (ah >>> 2)) ^ ((al << 25) | (ah >>> 7));

      // Sigma1
      let sigma1h = ((el << 18) | (eh >>> 14)) ^ ((el << 14) | (eh >>> 18)) ^ ((eh << 23) | (el >>> 9));
      let sigma1l = ((eh << 18) | (el >>> 14)) ^ ((eh << 14) | (el >>> 18)) ^ ((el << 23) | (eh >>> 9));

      // K(round)
      let krh = this.K[i * 2];
      let krl = this.K[i * 2 + 1];

      // t1 = h + sigma1 + ch + K(round) + W(round)
      let t1l = hl + sigma1l;
      let t1h = hh + sigma1h + ((t1l >>> 0) < (hl >>> 0) ? 1 : 0);
      t1l += chl;
      t1h += chh + ((t1l >>> 0) < (chl >>> 0) ? 1 : 0);
      t1l += krl;
      t1h += krh + ((t1l >>> 0) < (krl >>> 0) ? 1 : 0);
      t1l = t1l + wrl | 0;
      t1h += wrh + ((t1l >>> 0) < (wrl >>> 0) ? 1 : 0);

      // t2 = sigma0 + maj
      let t2l = sigma0l + majl;
      let t2h = sigma0h + majh + ((t2l >>> 0) < (sigma0l >>> 0) ? 1 : 0);

      // update working variables
      hh = gh;
      hl = gl;
      gh = fh;
      gl = fl;
      fh = eh;
      fl = el;
      el = (dl + t1l) | 0;
      eh = (dh + t1h + ((el >>> 0) < (dl >>> 0) ? 1 : 0)) | 0;
      dh = ch;
      dl = cl;
      ch = bh;
      cl = bl;
      bh = ah;
      bl = al;
      al = (t1l + t2l) | 0;
      ah = (t1h + t2h + ((al >>> 0) < (t1l >>> 0) ? 1 : 0)) | 0;
    }

    // intermediate hash
    h0l = h[1] = (h0l + al) | 0;
    h[0] = (h0h + ah + ((h0l >>> 0) < (al >>> 0) ? 1 : 0)) | 0;
    h1l = h[3] = (h1l + bl) | 0;
    h[2] = (h1h + bh + ((h1l >>> 0) < (bl >>> 0) ? 1 : 0)) | 0;
    h2l = h[5] = (h2l + cl) | 0;
    h[4] = (h2h + ch + ((h2l >>> 0) < (cl >>> 0) ? 1 : 0)) | 0;
    h3l = h[7] = (h3l + dl) | 0;
    h[6] = (h3h + dh + ((h3l >>> 0) < (dl >>> 0) ? 1 : 0)) | 0;
    h4l = h[9] = (h4l + el) | 0;
    h[8] = (h4h + eh + ((h4l >>> 0) < (el >>> 0) ? 1 : 0)) | 0;
    h5l = h[11] = (h5l + fl) | 0;
    h[10] = (h5h + fh + ((h5l >>> 0) < (fl >>> 0) ? 1 : 0)) | 0;
    h6l = h[13] = (h6l + gl) | 0;
    h[12] = (h6h + gh + ((h6l >>> 0) < (gl >>> 0) ? 1 : 0)) | 0;
    h7l = h[15] = (h7l + hl) | 0;
    h[14] = (h7h + hh + ((h7l >>> 0) < (hl >>> 0) ? 1 : 0)) | 0;
  }


  /**
   * Update the hash with additional message data
   * @param {Uint8Array} msg Additional message data as byte array
   * @return {SHA512} this
   */
  update(msg?: Uint8Array): SHA512 {
      msg = msg || new Uint8Array(0);
      // process the msg as many times as possible, the rest is stored in the buffer
      // message is processed in 1024 bit (128 byte chunks)
      for (let i = 0; i < msg.length; i++) {
        this.buffer[this.bufferIndex++] = msg[i];
        if (this.bufferIndex === 128) {
          this.transform();
          this.bufferIndex = 0;
        }
      }

      // counter update (number of message bits)
      let c = this.count;
      if ((c[0] += (msg.length << 3)) < (msg.length << 3))
        c[1]++;
      c[1] += (msg.length >>> 29);

    return this;
  }


  /**
   * Finalize the hash with additional message data
   * @param {Uint8Array} msg Additional message data as byte array
   * @return {Uint8Array} Hash as 64 byte array
   */
  digest(msg?: Uint8Array): Uint8Array {
    this.update(msg);

        // append '1'
        var b = this.buffer, idx = this.bufferIndex;
        b[idx++] = 0x80;

        // zeropad up to byte pos 112
        while (idx !== 112) {
          if (idx === 128) {
            this.transform();
            idx = 0;
          }
          b[idx++] = 0;
        }

        // append length in bits
        let c = this.count;
        b[112] = b[113] = b[114] = b[115] = b[116] = b[117] = b[118] = b[119] = 0;
        b[120] = (c[1] >>> 24) & 0xff;
        b[121] = (c[1] >>> 16) & 0xff;
        b[122] = (c[1] >>> 8) & 0xff;
        b[123] = (c[1] >>> 0) & 0xff;
        b[124] = (c[0] >>> 24) & 0xff;
        b[125] = (c[0] >>> 16) & 0xff;
        b[126] = (c[0] >>> 8) & 0xff;
        b[127] = (c[0] >>> 0) & 0xff;
        this.transform();

        // return the hash as byte array
        let hash = new Uint8Array(64);
        for (let i = 0; i < 16; i++) {
          hash[(i << 2) + 0] = (this.H[i] >>> 24) & 0xff;
          hash[(i << 2) + 1] = (this.H[i] >>> 16) & 0xff;
          hash[(i << 2) + 2] = (this.H[i] >>> 8) & 0xff;
          hash[(i << 2) + 3] = (this.H[i] >>> 0) & 0xff;
        }

        // clear internal states and prepare for new hash
        this.init();

    return hash;
  }


  /**
   * All in one step
   * @param {Uint8Array} msg Additional message data
   * @return {Uint8Array} Hash as 64 byte array
   */
  hash(msg?: Uint8Array): Uint8Array {
    return this.init().digest(msg);
  }


  /**
   * Performs a quick selftest
   * @return {Boolean} True if successful
   */
  selftest(): boolean {
    let cumulative = new SHA512(), sha = new SHA512();
    let toBeHashed = '', hash;
    for (let i = 0; i < 10; i++) {
      for (let n = 100 * i; n < 100 * (i + 1); n++) {
        hash = Convert.bin2hex(sha.hash(Convert.str2bin(toBeHashed)));
        cumulative.update(Convert.str2bin(hash));
        toBeHashed = (hash.substring(0, 2) + toBeHashed).substring(0, n + 1);
      }
    }
    hash = Convert.bin2hex(cumulative.digest());
    return hash === '602923787640dd6d77a99b101c379577a4054df2d61f39c74172cafa2d9f5b26a11b40b7ba4cdc87e84a4ab91b85391cb3e1c0200f3e3d5e317486aae7bebbf3';
  }
}
