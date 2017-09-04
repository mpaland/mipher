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
// \brief curve25519 (scalarmult and ed25519) implementation
//
// inspired by:
// https://github.com/rev22/curve255js
// https://github.com/meganz/jodid25519
//
// test vectors partially taken from:
// https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-03
//
// additional documentation:
// https://blog.mozilla.org/warner/2011/11/29/ed25519-keys
// http://csrc.nist.gov/groups/ST/ecc-workshop-2015/presentations/session6-chou-tung.pdf
//
///////////////////////////////////////////////////////////////////////////////

import {Convert, Util, Signature} from './base';
import {SHA512} from './SHA512';


/**
 * Curve25519 class
 */
export class Curve25519 {
  gf0: Float64Array;
  gf1: Float64Array;
  D:   Float64Array;
  D2:  Float64Array;
  I:   Float64Array;
  _9:  Uint8Array;
  _121665: Float64Array;

  /**
   * Curve25519 ctor
   */
  constructor() {
    this.gf0 = this.gf();
    this.gf1 = this.gf([1]);
    this._9 = new Uint8Array(32);
    this._9[0] = 9;
    this._121665 = this.gf([0xdb41, 1]);
    this.D = this.gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]);
    this.D2 = this.gf([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]);
    this.I = this.gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83]);
  }


  gf(init?: Array<number>): Float64Array {
    let r = new Float64Array(16);
    if (init) {
      for (let i = 0; i < init.length; i++) {
        r[i] = init[i];
      }
    }
    return r;
  }


  verify_32(x: Uint8Array, xi: number, y: Uint8Array, yi: number): number {
    let d = 0;
    for (let i = 0; i < 32; i++) {
      d |= x[xi + i] ^ y[yi + i];
    }
    return (1 & ((d - 1) >>> 8)) - 1;
  };


  private A(o: Float64Array, a: Float64Array, b: Float64Array) {
    for (let i = 0; i < 16; i++) {
      o[i] = a[i] + b[i];
    }
  }


  private Z(o: Float64Array, a: Float64Array, b:Float64Array) {
    for (let i = 0; i < 16; i++) {
      o[i] = a[i] - b[i];
    }
  }


  M(o: Float64Array, a: Float64Array, b: Float64Array) {
    let v, c,
      t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0,
      t8 = 0, t9 = 0, t10 = 0, t11 = 0, t12 = 0, t13 = 0, t14 = 0, t15 = 0,
      t16 = 0, t17 = 0, t18 = 0, t19 = 0, t20 = 0, t21 = 0, t22 = 0, t23 = 0,
      t24 = 0, t25 = 0, t26 = 0, t27 = 0, t28 = 0, t29 = 0, t30 = 0,
      b0 = b[0],
      b1 = b[1],
      b2 = b[2],
      b3 = b[3],
      b4 = b[4],
      b5 = b[5],
      b6 = b[6],
      b7 = b[7],
      b8 = b[8],
      b9 = b[9],
      b10 = b[10],
      b11 = b[11],
      b12 = b[12],
      b13 = b[13],
      b14 = b[14],
      b15 = b[15];

    v = a[0];
    t0 += v * b0;
    t1 += v * b1;
    t2 += v * b2;
    t3 += v * b3;
    t4 += v * b4;
    t5 += v * b5;
    t6 += v * b6;
    t7 += v * b7;
    t8 += v * b8;
    t9 += v * b9;
    t10 += v * b10;
    t11 += v * b11;
    t12 += v * b12;
    t13 += v * b13;
    t14 += v * b14;
    t15 += v * b15;
    v = a[1];
    t1 += v * b0;
    t2 += v * b1;
    t3 += v * b2;
    t4 += v * b3;
    t5 += v * b4;
    t6 += v * b5;
    t7 += v * b6;
    t8 += v * b7;
    t9 += v * b8;
    t10 += v * b9;
    t11 += v * b10;
    t12 += v * b11;
    t13 += v * b12;
    t14 += v * b13;
    t15 += v * b14;
    t16 += v * b15;
    v = a[2];
    t2 += v * b0;
    t3 += v * b1;
    t4 += v * b2;
    t5 += v * b3;
    t6 += v * b4;
    t7 += v * b5;
    t8 += v * b6;
    t9 += v * b7;
    t10 += v * b8;
    t11 += v * b9;
    t12 += v * b10;
    t13 += v * b11;
    t14 += v * b12;
    t15 += v * b13;
    t16 += v * b14;
    t17 += v * b15;
    v = a[3];
    t3 += v * b0;
    t4 += v * b1;
    t5 += v * b2;
    t6 += v * b3;
    t7 += v * b4;
    t8 += v * b5;
    t9 += v * b6;
    t10 += v * b7;
    t11 += v * b8;
    t12 += v * b9;
    t13 += v * b10;
    t14 += v * b11;
    t15 += v * b12;
    t16 += v * b13;
    t17 += v * b14;
    t18 += v * b15;
    v = a[4];
    t4 += v * b0;
    t5 += v * b1;
    t6 += v * b2;
    t7 += v * b3;
    t8 += v * b4;
    t9 += v * b5;
    t10 += v * b6;
    t11 += v * b7;
    t12 += v * b8;
    t13 += v * b9;
    t14 += v * b10;
    t15 += v * b11;
    t16 += v * b12;
    t17 += v * b13;
    t18 += v * b14;
    t19 += v * b15;
    v = a[5];
    t5 += v * b0;
    t6 += v * b1;
    t7 += v * b2;
    t8 += v * b3;
    t9 += v * b4;
    t10 += v * b5;
    t11 += v * b6;
    t12 += v * b7;
    t13 += v * b8;
    t14 += v * b9;
    t15 += v * b10;
    t16 += v * b11;
    t17 += v * b12;
    t18 += v * b13;
    t19 += v * b14;
    t20 += v * b15;
    v = a[6];
    t6 += v * b0;
    t7 += v * b1;
    t8 += v * b2;
    t9 += v * b3;
    t10 += v * b4;
    t11 += v * b5;
    t12 += v * b6;
    t13 += v * b7;
    t14 += v * b8;
    t15 += v * b9;
    t16 += v * b10;
    t17 += v * b11;
    t18 += v * b12;
    t19 += v * b13;
    t20 += v * b14;
    t21 += v * b15;
    v = a[7];
    t7 += v * b0;
    t8 += v * b1;
    t9 += v * b2;
    t10 += v * b3;
    t11 += v * b4;
    t12 += v * b5;
    t13 += v * b6;
    t14 += v * b7;
    t15 += v * b8;
    t16 += v * b9;
    t17 += v * b10;
    t18 += v * b11;
    t19 += v * b12;
    t20 += v * b13;
    t21 += v * b14;
    t22 += v * b15;
    v = a[8];
    t8 += v * b0;
    t9 += v * b1;
    t10 += v * b2;
    t11 += v * b3;
    t12 += v * b4;
    t13 += v * b5;
    t14 += v * b6;
    t15 += v * b7;
    t16 += v * b8;
    t17 += v * b9;
    t18 += v * b10;
    t19 += v * b11;
    t20 += v * b12;
    t21 += v * b13;
    t22 += v * b14;
    t23 += v * b15;
    v = a[9];
    t9 += v * b0;
    t10 += v * b1;
    t11 += v * b2;
    t12 += v * b3;
    t13 += v * b4;
    t14 += v * b5;
    t15 += v * b6;
    t16 += v * b7;
    t17 += v * b8;
    t18 += v * b9;
    t19 += v * b10;
    t20 += v * b11;
    t21 += v * b12;
    t22 += v * b13;
    t23 += v * b14;
    t24 += v * b15;
    v = a[10];
    t10 += v * b0;
    t11 += v * b1;
    t12 += v * b2;
    t13 += v * b3;
    t14 += v * b4;
    t15 += v * b5;
    t16 += v * b6;
    t17 += v * b7;
    t18 += v * b8;
    t19 += v * b9;
    t20 += v * b10;
    t21 += v * b11;
    t22 += v * b12;
    t23 += v * b13;
    t24 += v * b14;
    t25 += v * b15;
    v = a[11];
    t11 += v * b0;
    t12 += v * b1;
    t13 += v * b2;
    t14 += v * b3;
    t15 += v * b4;
    t16 += v * b5;
    t17 += v * b6;
    t18 += v * b7;
    t19 += v * b8;
    t20 += v * b9;
    t21 += v * b10;
    t22 += v * b11;
    t23 += v * b12;
    t24 += v * b13;
    t25 += v * b14;
    t26 += v * b15;
    v = a[12];
    t12 += v * b0;
    t13 += v * b1;
    t14 += v * b2;
    t15 += v * b3;
    t16 += v * b4;
    t17 += v * b5;
    t18 += v * b6;
    t19 += v * b7;
    t20 += v * b8;
    t21 += v * b9;
    t22 += v * b10;
    t23 += v * b11;
    t24 += v * b12;
    t25 += v * b13;
    t26 += v * b14;
    t27 += v * b15;
    v = a[13];
    t13 += v * b0;
    t14 += v * b1;
    t15 += v * b2;
    t16 += v * b3;
    t17 += v * b4;
    t18 += v * b5;
    t19 += v * b6;
    t20 += v * b7;
    t21 += v * b8;
    t22 += v * b9;
    t23 += v * b10;
    t24 += v * b11;
    t25 += v * b12;
    t26 += v * b13;
    t27 += v * b14;
    t28 += v * b15;
    v = a[14];
    t14 += v * b0;
    t15 += v * b1;
    t16 += v * b2;
    t17 += v * b3;
    t18 += v * b4;
    t19 += v * b5;
    t20 += v * b6;
    t21 += v * b7;
    t22 += v * b8;
    t23 += v * b9;
    t24 += v * b10;
    t25 += v * b11;
    t26 += v * b12;
    t27 += v * b13;
    t28 += v * b14;
    t29 += v * b15;
    v = a[15];
    t15 += v * b0;
    t16 += v * b1;
    t17 += v * b2;
    t18 += v * b3;
    t19 += v * b4;
    t20 += v * b5;
    t21 += v * b6;
    t22 += v * b7;
    t23 += v * b8;
    t24 += v * b9;
    t25 += v * b10;
    t26 += v * b11;
    t27 += v * b12;
    t28 += v * b13;
    t29 += v * b14;
    t30 += v * b15;

    t0 += 38 * t16;
    t1 += 38 * t17;
    t2 += 38 * t18;
    t3 += 38 * t19;
    t4 += 38 * t20;
    t5 += 38 * t21;
    t6 += 38 * t22;
    t7 += 38 * t23;
    t8 += 38 * t24;
    t9 += 38 * t25;
    t10 += 38 * t26;
    t11 += 38 * t27;
    t12 += 38 * t28;
    t13 += 38 * t29;
    t14 += 38 * t30;
    // t15 left as it is

    // first car
    c = 1;
    v = t0  + c + 65535; c = Math.floor(v / 65536); t0  = v - c * 65536;
    v = t1  + c + 65535; c = Math.floor(v / 65536); t1  = v - c * 65536;
    v = t2  + c + 65535; c = Math.floor(v / 65536); t2  = v - c * 65536;
    v = t3  + c + 65535; c = Math.floor(v / 65536); t3  = v - c * 65536;
    v = t4  + c + 65535; c = Math.floor(v / 65536); t4  = v - c * 65536;
    v = t5  + c + 65535; c = Math.floor(v / 65536); t5  = v - c * 65536;
    v = t6  + c + 65535; c = Math.floor(v / 65536); t6  = v - c * 65536;
    v = t7  + c + 65535; c = Math.floor(v / 65536); t7  = v - c * 65536;
    v = t8  + c + 65535; c = Math.floor(v / 65536); t8  = v - c * 65536;
    v = t9  + c + 65535; c = Math.floor(v / 65536); t9  = v - c * 65536;
    v = t10 + c + 65535; c = Math.floor(v / 65536); t10 = v - c * 65536;
    v = t11 + c + 65535; c = Math.floor(v / 65536); t11 = v - c * 65536;
    v = t12 + c + 65535; c = Math.floor(v / 65536); t12 = v - c * 65536;
    v = t13 + c + 65535; c = Math.floor(v / 65536); t13 = v - c * 65536;
    v = t14 + c + 65535; c = Math.floor(v / 65536); t14 = v - c * 65536;
    v = t15 + c + 65535; c = Math.floor(v / 65536); t15 = v - c * 65536;
    t0 += c - 1 + 37 * (c - 1);

    // second car
    c = 1;
    v = t0  + c + 65535; c = Math.floor(v / 65536); t0  = v - c * 65536;
    v = t1  + c + 65535; c = Math.floor(v / 65536); t1  = v - c * 65536;
    v = t2  + c + 65535; c = Math.floor(v / 65536); t2  = v - c * 65536;
    v = t3  + c + 65535; c = Math.floor(v / 65536); t3  = v - c * 65536;
    v = t4  + c + 65535; c = Math.floor(v / 65536); t4  = v - c * 65536;
    v = t5  + c + 65535; c = Math.floor(v / 65536); t5  = v - c * 65536;
    v = t6  + c + 65535; c = Math.floor(v / 65536); t6  = v - c * 65536;
    v = t7  + c + 65535; c = Math.floor(v / 65536); t7  = v - c * 65536;
    v = t8  + c + 65535; c = Math.floor(v / 65536); t8  = v - c * 65536;
    v = t9  + c + 65535; c = Math.floor(v / 65536); t9  = v - c * 65536;
    v = t10 + c + 65535; c = Math.floor(v / 65536); t10 = v - c * 65536;
    v = t11 + c + 65535; c = Math.floor(v / 65536); t11 = v - c * 65536;
    v = t12 + c + 65535; c = Math.floor(v / 65536); t12 = v - c * 65536;
    v = t13 + c + 65535; c = Math.floor(v / 65536); t13 = v - c * 65536;
    v = t14 + c + 65535; c = Math.floor(v / 65536); t14 = v - c * 65536;
    v = t15 + c + 65535; c = Math.floor(v / 65536); t15 = v - c * 65536;
    t0 += c - 1 + 37 * (c - 1);

    o[0]  = t0;
    o[1]  = t1;
    o[2]  = t2;
    o[3]  = t3;
    o[4]  = t4;
    o[5]  = t5;
    o[6]  = t6;
    o[7]  = t7;
    o[8]  = t8;
    o[9]  = t9;
    o[10] = t10;
    o[11] = t11;
    o[12] = t12;
    o[13] = t13;
    o[14] = t14;
    o[15] = t15;
  }


  private S(o: Float64Array, a: Float64Array) {
    this.M(o, a, a);
  }


  add(p, q) {
    let a = this.gf(), b = this.gf(), c = this.gf(),
        d = this.gf(), e = this.gf(), f = this.gf(),
        g = this.gf(), h = this.gf(), t = this.gf();

    this.Z(a, p[1], p[0]);
    this.Z(t, q[1], q[0]);
    this.M(a, a, t);
    this.A(b, p[0], p[1]);
    this.A(t, q[0], q[1]);
    this.M(b, b, t);
    this.M(c, p[3], q[3]);
    this.M(c, c, this.D2);
    this.M(d, p[2], q[2]);
    this.A(d, d, d);
    this.Z(e, b, a);
    this.Z(f, d, c);
    this.A(g, d, c);
    this.A(h, b, a);
    this.M(p[0], e, f);
    this.M(p[1], h, g);
    this.M(p[2], g, f);
    this.M(p[3], e, h);
  }


  set25519(r, a) {
    for (let i = 0; i < 16; i++) {
      r[i] = a[i] | 0;
    }
  }


  private car25519(o) {
    let i, v, c = 1;
    for (i = 0; i < 16; i++) {
      v = o[i] + c + 65535;
      c = Math.floor(v / 65536);
      o[i] = v - c * 65536;
    }
    o[0] += c - 1 + 37 * (c - 1);
  }


  private sel25519(p: Float64Array, q: Float64Array, b: number) {
    let i, t, c = ~(b - 1);
    for (i = 0; i < 16; i++) {
      t = c & (p[i] ^ q[i]);
      p[i] ^= t;
      q[i] ^= t;
    }
  };


  inv25519(o: Float64Array, i: Float64Array) {
    let a, c = this.gf();
    for (a = 0; a < 16; a++) {
      c[a] = i[a];
    }
    for (a = 253; a >= 0; a--) {
      this.S(c, c);
      if (a !== 2 && a !== 4) {
        this.M(c, c, i);
      }
    }
    for (a = 0; a < 16; a++) {
      o[a] = c[a];
    }
  }


  private neq25519(a: Float64Array, b: Float64Array): number {
    let c = new Uint8Array(32), d = new Uint8Array(32);
    this.pack25519(c, a);
    this.pack25519(d, b);
    return this.verify_32(c, 0, d, 0);
  }


  par25519(a: Float64Array): number {
    let d = new Uint8Array(32);
    this.pack25519(d, a);
    return d[0] & 1;
  }


  private pow2523(o: Float64Array, i: Float64Array) {
    let a, c = this.gf();
    for (a = 0; a < 16; a++)
      c[a] = i[a];
    for (a = 250; a >= 0; a--) {
      this.S(c, c);
      if (a !== 1) this.M(c, c, i);
    }
    for (a = 0; a < 16; a++)
      o[a] = c[a];
  }


  cswap(p: Array<Float64Array>, q: Array<Float64Array>, b: number) {
    for (let i = 0; i < 4; i++) {
      this.sel25519(p[i], q[i], b);
    }
  }


  pack25519(o: Uint8Array, n: Float64Array) {
    let i, m = this.gf(), t = this.gf();
    for (i = 0; i < 16; i++) {
      t[i] = n[i];
    }
    this.car25519(t);
    this.car25519(t);
    this.car25519(t);
    for (let j = 0; j < 2; j++) {
      m[0] = t[0] - 0xffed;
      for (i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i - 1] >>> 16) & 1);
        m[i - 1] &= 0xffff;
      }
      m[15] = t[15] - 0x7fff - ((m[14] >>> 16) & 1);
      let b = (m[15] >>> 16) & 1;
      m[14] &= 0xffff;
      this.sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
      o[2 * i] = t[i] & 0xff;
      o[2 * i + 1] = t[i] >>> 8;
    }
  }


  private unpack25519(o: Float64Array, n: Uint8Array) {
    for (let i = 0; i < 16; i++) {
      o[i] = n[2 * i] + (n[2 * i + 1] << 8);
    }
    o[15] &= 0x7fff;
  }


  unpackneg(r, p): number {
    let t = this.gf(), chk = this.gf(), num = this.gf(), den = this.gf(), den2 = this.gf(), den4 = this.gf(), den6 = this.gf();

    this.set25519(r[2], this.gf1);
    this.unpack25519(r[1], p);
    this.S(num, r[1]);
    this.M(den, num, this.D);
    this.Z(num, num, r[2]);
    this.A(den, r[2], den);

    this.S(den2, den);
    this.S(den4, den2);
    this.M(den6, den4, den2);
    this.M(t, den6, num);
    this.M(t, t, den);

    this.pow2523(t, t);
    this.M(t, t, num);
    this.M(t, t, den);
    this.M(t, t, den);
    this.M(r[0], t, den);

    this.S(chk, r[0]);
    this.M(chk, chk, den);
    if (this.neq25519(chk, num)) this.M(r[0], r[0], this.I);

    this.S(chk, r[0]);
    this.M(chk, chk, den);
    if (this.neq25519(chk, num))
      return -1;

    if (this.par25519(r[0]) === (p[31] >>> 7)) this.Z(r[0], this.gf0, r[0]);

    this.M(r[3], r[0], r[1]);
    return 0;
  }


  /**
   * Internal scalar mult function
   * @param q Result
   * @param s Secret key
   * @param p Public key
   */
  private crypto_scalarmult(q: Uint8Array, s: Uint8Array, p: Uint8Array) {
    let z = new Uint8Array(s);
    let x = new Float64Array(80), r, i;
    let a = this.gf(), b = this.gf(), c = this.gf(),
        d = this.gf(), e = this.gf(), f = this.gf();

    this.unpack25519(x, p);
    for (i = 0; i < 16; i++) {
      b[i] = x[i];
      d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
      r = (z[i >>> 3] >>> (i & 7)) & 1;
      this.sel25519(a, b, r);
      this.sel25519(c, d, r);
      this.A(e, a, c);
      this.Z(a, a, c);
      this.A(c, b, d);
      this.Z(b, b, d);
      this.S(d, e);
      this.S(f, a);
      this.M(a, c, a);
      this.M(c, b, e);
      this.A(e, a, c);
      this.Z(a, a, c);
      this.S(b, a);
      this.Z(c, d, f);
      this.M(a, c, this._121665);
      this.A(a, a, d);
      this.M(c, c, a);
      this.M(a, d, f);
      this.M(d, b, x);
      this.S(b, e);
      this.sel25519(a, b, r);
      this.sel25519(c, d, r);
    }
    for (i = 0; i < 16; i++) {
      x[i + 16] = a[i];
      x[i + 32] = c[i];
      x[i + 48] = b[i];
      x[i + 64] = d[i];
    }
    let x32 = x.subarray(32);
    let x16 = x.subarray(16);
    this.inv25519(x32, x32);
    this.M(x16, x16, x32);
    this.pack25519(q, x16);
  };


  /**
   * Generate the common key as the produkt of sk1 * pk2
   * @param {Uint8Array} sk A 32 byte secret key of pair 1
   * @param {Uint8Array} pk A 32 byte public key of pair 2
   * @return {Uint8Array} sk * pk
   */
  scalarMult(sk: Uint8Array, pk: Uint8Array): Uint8Array {
    let q = new Uint8Array(32);
    this.crypto_scalarmult(q, sk, pk);
    return q;
  }


  /**
   * Generate a curve 25519 keypair
   * @param {Uint8Array} seed A 32 byte cryptographic secure random array. This is basically the secret key
   * @param {Object} Returns sk (Secret key) and pk (Public key) as 32 byte typed arrays
   */
  generateKeys(seed: Uint8Array): { sk: Uint8Array, pk: Uint8Array } {
    let sk = new Uint8Array(seed);
    let pk = new Uint8Array(32);
    if (sk.length !== 32) {
      return;
    }

    // harden the secret key by clearing bit 0, 1, 2, 255 and setting bit 254
    // clearing the lower 3 bits of the secret key ensures that is it a multiple of 8
    sk[0]  &= 0xf8;
    sk[31] &= 0x7f;
    sk[31] |= 0x40;

    this.crypto_scalarmult(pk, sk, this._9);
    return { sk: sk, pk: pk };
  }


  /**
   * Performs a quick selftest
   * @param {Boolean} Returns true if selftest passed
   */
  selftest(): boolean {
    const key = [
      {
        sk: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        pk: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
      },
      {
        sk: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        pk: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
      }
    ];
    const mul = [
      {
        sk: "0300000000000000000000000000000000000000000000000000000000000000",
        pk: "0900000000000000000000000000000000000000000000000000000000000000",
        sp: "123c71fbaf030ac059081c62674e82f864ba1bc2914d5345e6ab576d1abc121c"
      },
      {
        sk: "847c4978577d530dcb491d58bcc9cba87f9e075e6e02c003f27aee503cecb641",
        pk: "57faa45404f10f1e4733047eca8f2f3001c12aa859e40d74cf59afaabe441d45",
        sp: "b3c49b94dcc349ba05ca13521e19d1b93fc472f1545bbf9bdf7ec7b442be4a2c"
      }
    ];

    // key generation
    let sk, pk, sp;
    for (let i = 0, len = key.length; i < len; i++) {
      sk = Convert.hex2bin(key[i].sk);
      pk = Convert.hex2bin(key[i].pk);
      if (!Util.compare(this.generateKeys(sk).pk, pk)) return false;
    }

    // scalar multiplication
    for (let i = 0, len = mul.length; i < len; i++) {
      sk = Convert.hex2bin(mul[i].sk);
      pk = Convert.hex2bin(mul[i].pk);
      sp = Convert.hex2bin(mul[i].sp);
      if (!Util.compare(this.scalarMult(sk, pk), sp)) return false;
    }

    return true;
  }
}


///////////////////////////////////////////////////////////////////////////////
// E D 2 5 5 1 9

/**
 * Ed25519 class
 */
export class Ed25519 implements Signature {
  curve:  Curve25519;
  sha512: SHA512;
  X:      Float64Array;
  Y:      Float64Array;


  /**
   * Ed25519 ctor
   */
  constructor() {
    this.curve  = new Curve25519();
    this.sha512 = new SHA512();
    this.X = this.curve.gf([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]);
    this.Y = this.curve.gf([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]);
  }


  private pack(r: Uint8Array, p: Array<Float64Array>) {
    let CURVE = this.curve;
    let tx = CURVE.gf(),
        ty = CURVE.gf(),
        zi = CURVE.gf();
    CURVE.inv25519(zi, p[2]);
    CURVE.M(tx, p[0], zi);
    CURVE.M(ty, p[1], zi);
    CURVE.pack25519(r, ty);
    r[31] ^= CURVE.par25519(tx) << 7;
  }


  private modL(r: Uint8Array, x: Float64Array) {
    let L = new Uint8Array([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]);
    let carry, i, j, k;
    for (i = 63; i >= 32; --i) {
      carry = 0;
      for (j = i - 32, k = i - 12; j < k; ++j) {
        x[j] += carry - 16 * x[i] * L[j - (i - 32)];
        carry = (x[j] + 128) >> 8;  // caution: NO >>> here, carry is needed!!!
        x[j] -= carry * 256;
      }
      x[j] += carry;
      x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) {
      x[j] += carry - (x[31] >> 4) * L[j];
      carry = x[j] >> 8;            // caution: NO >>> here, carry is needed!!!
      x[j] &= 255;
    }
    for (j = 0; j < 32; j++) x[j] -= carry * L[j];
    for (i = 0; i < 32; i++) {
      x[i+1] += x[i] >>> 8;
      r[i] = x[i] & 0xff;
    }
  }


  private reduce(r: Uint8Array) {
    let x = new Float64Array(64), i;
    for (i = 0; i < 64; i++) x[i] = r[i];
    for (i = 0; i < 64; i++) r[i] = 0;
    this.modL(r, x);
  }


  private scalarmult(p: Array<Float64Array>, q: Array<Float64Array>, s: Uint8Array) {
    let CURVE = this.curve;
    CURVE.set25519(p[0], CURVE.gf0);
    CURVE.set25519(p[1], CURVE.gf1);
    CURVE.set25519(p[2], CURVE.gf1);
    CURVE.set25519(p[3], CURVE.gf0);
    for (let i = 255; i >= 0; --i) {
      let b = (s[(i / 8)|0] >>> (i & 7)) & 1;
      CURVE.cswap(p, q, b);
      CURVE.add(q, p);
      CURVE.add(p, p);
      CURVE.cswap(p, q, b);
    }
  }


  private scalarbase(p: Array<Float64Array>, s: Uint8Array) {
    let CURVE = this.curve;
    let q = [CURVE.gf(), CURVE.gf(), CURVE.gf(), CURVE.gf()];
    CURVE.set25519(q[0], this.X);
    CURVE.set25519(q[1], this.Y);
    CURVE.set25519(q[2], CURVE.gf1);
    CURVE.M(q[3], this.X, this.Y);
    this.scalarmult(p, q, s);
  };


  /**
   * Generate an ed25519 keypair
   * Some implementations represent the secret key as a combination of sk and pk. mipher just uses the sk itself.
   * @param {Uint8Array} seed A 32 byte cryptographic secure random array. This is basically the secret key
   * @param {Object} Returns sk (Secret key) and pk (Public key) as 32 byte typed arrays
   */
  generateKeys(seed: Uint8Array): { sk: Uint8Array, pk: Uint8Array } {
    let sk = new Uint8Array(seed);
    let pk = new Uint8Array(32);
    if (sk.length !== 32) {
      return;
    }

    let p = [this.curve.gf(), this.curve.gf(), this.curve.gf(), this.curve.gf()];
    let h = this.sha512.hash(sk).subarray(0, 32);

    // harden the secret key by clearing bit 0, 1, 2, 255 and setting bit 254
    // clearing the lower 3 bits of the secret key ensures that is it a multiple of 8
    h[0]  &= 0xf8;
    h[31] &= 0x7f;
    h[31] |= 0x40;

    this.scalarbase(p, h);
    this.pack(pk, p);
    return { sk: sk, pk: pk };
  }


  /**
   * Generate a message signature
   * @param {Uint8Array} msg Message to be signed as byte array
   * @param {Uint8Array} sk Secret key as 32 byte array
   * @param {Uint8Array} pk Public key as 32 byte array
   * @param {Uint8Array} Returns the signature as 64 byte typed array
   */
  sign(msg: Uint8Array, sk: Uint8Array, pk: Uint8Array): Uint8Array {
    let CURVE = this.curve;
    let p = [CURVE.gf(), CURVE.gf(), CURVE.gf(), CURVE.gf()];
    let h = this.sha512.hash(sk);

    if (sk.length !== 32) return;
    if (pk.length !== 32) return;

    h[ 0] &= 0xf8;
    h[31] &= 0x7f;
    h[31] |= 0x40;

    // compute r = SHA512(h[32-63] || M)
    let s = new Uint8Array(64);
    let r = this.sha512.init().update(h.subarray(32)).digest(msg);
    this.reduce(r);
    this.scalarbase(p, r);
    this.pack(s, p);

    // compute k = SHA512(R || A || M)
    let k = this.sha512.init().update(s.subarray(0,32)).update(pk).digest(msg);
    this.reduce(k);

    // compute s = (r + k a) mod q
    let x = new Float64Array(64), i;
    for (i = 0; i < 32; i++) x[i] = r[i];
    for (i = 0; i < 32; i++) {
      for (let j = 0; j < 32; j++) {
        x[i+j] += k[i] * h[j];
      }
    }
    this.modL(s.subarray(32), x);

    return s;
  }


  /**
   * Verify a message signature
   * @param {Uint8Array} msg Message to be signed as byte array
   * @param {Uint8Array} pk Public key as 32 byte array
   * @param {Uint8Array} sig Signature as 64 byte array
   * @param {Boolean} Returns true if signature is valid
   */
  verify(msg: Uint8Array, pk: Uint8Array, sig: Uint8Array): boolean {
    let CURVE = this.curve;
    let p = [CURVE.gf(), CURVE.gf(), CURVE.gf(), CURVE.gf()],
        q = [CURVE.gf(), CURVE.gf(), CURVE.gf(), CURVE.gf()];

    if (sig.length !== 64) return false;
    if (pk.length !== 32) return false;
    if (CURVE.unpackneg(q, pk)) return false;

    // compute k = SHA512(R || A || M)
    let k = this.sha512.init().update(sig.subarray(0,32)).update(pk).digest(msg);
    this.reduce(k);
    this.scalarmult(p, q, k);

    let t = new Uint8Array(32);
    this.scalarbase(q, sig.subarray(32));
    CURVE.add(p, q);
    this.pack(t, p);

    return CURVE.verify_32(sig, 0, t, 0) === 0;
  }


  /**
   * Performs a quick selftest
   * @param {Boolean} Returns true if selftest passed
   */
  selftest(): boolean {
    const v = [
      { sk: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        pk: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        m : "",
        s : "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
      { sk: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        pk: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        m : "72",
        s : "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
      { sk: "5b5a619f8ce1c66d7ce26e5a2ae7b0c04febcd346d286c929e19d0d5973bfef9",
        pk: "6fe83693d011d111131c4f3fbaaa40a9d3d76b30012ff73bb0e39ec27ab18257",
        m : "5a8d9d0a22357e6655f9c785",
        s : "0f9ad9793033a2fa06614b277d37381e6d94f65ac2a5a94558d09ed6ce922258c1a567952e863ac94297aec3c0d0c8ddf71084e504860bb6ba27449b55adc40e" }
    ];

    for (let i = 0; i < v.length; i++) {
      let sk = Convert.hex2bin(v[i].sk),
          pk = Convert.hex2bin(v[i].pk),
          m  = Convert.hex2bin(v[i].m),
          s  = Convert.hex2bin(v[i].s);

      // sign test
      if (!Util.compare(this.sign(m, sk, pk), s)) return false;

      // verify test
      if (!this.verify(m, pk, s)) return false;
      s[i % 64] ^= 0x01;
      if (this.verify(m, pk, s)) return false;
    }

    return true;
  }
}
