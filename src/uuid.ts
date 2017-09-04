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
// \brief UUID generation after RFC 4122
//        Generates 128 bit UUIDs as V1 (time based) or V4 (random based) 
//        https://tools.ietf.org/html/rfc4122
//
///////////////////////////////////////////////////////////////////////////////

import {Convert} from './base';


/**
 * UUID class
 */
export class UUID {
  msec:     number;
  nsec:     number;
  clockseq: number;

  /**
   * UUID ctor
   */
  constructor() {
    this.msec = 0;
    this.nsec = 0;
    this.clockseq = null;
  }


  /**
   * Create a time based V1 UUID
   * @param {Uint8Array} node 6 byte array of unique node identifier like the MAC address or TRUE random data
   * @param {Uint8Array} clockseq Optional 2 byte array of random data for clockseq init
   * @return {Uint8Array} UUID as 16 byte typed array or 'undefined' if error
   */
  v1(node: Uint8Array, clockseq?: Uint8Array): Uint8Array {
    let msec, nsec;
    if (typeof performance !== 'undefined' && performance.timing && typeof performance.now === 'function') {
      msec = performance.timing.navigationStart + performance.now();
      nsec = Math.floor((msec % 1) * 10000);  // unit is [100 ns] now
      msec = Math.floor(msec);
    }
    else {
      msec = Date.now();
      nsec = 0;
    }

    // convert from unix epoch to Gregorian epoch
    msec += 12219292800000;

    // increment nsec if time is equal to last created value
    if (msec === this.msec && nsec === this.nsec) {
      nsec++;
    }

    // bump clockseq on clock regression
    if (this.clockseq === null) {
      // init clockseq
      let cs = clockseq || Convert.str2bin(Math.random().toString());
      this.clockseq = (cs[0] | 0) + (cs[1] << 8);
    }
    let dt = (msec - this.msec) + (nsec - this.nsec) / 10000;
    if (dt < 0) {
      this.clockseq = (this.clockseq + 1) & 0x3fff;
      if (msec > this.msec) {
        nsec = 0;     // reset nsec if clock regresses
      }
    }

    this.msec = msec;
    this.nsec = nsec;
    let uuid = new Uint8Array(16), i = 0;

    // time_low
    var tl = ((msec & 0xfffffff) * 10000 + nsec) % 0x100000000;
    uuid[i++] = (tl >>> 24) & 0xff;
    uuid[i++] = (tl >>> 16) & 0xff;
    uuid[i++] = (tl >>>  8) & 0xff;
    uuid[i++] = (tl       ) & 0xff;

    // time_mid
    var tmh = (msec / 0x100000000 * 10000) & 0xfffffff;
    uuid[i++] = (tmh >>> 8) & 0xff;
    uuid[i++] = (tmh)       & 0xff;

    // time_high_and_version
    uuid[i++] = (tmh >>> 24) & 0x0f | 0x10;  // version is 'V1'
    uuid[i++] = (tmh >>> 16) & 0xff;

    // clock_seq_hi_and_reserved
    uuid[i++] = (this.clockseq >>> 8) & 0x3f | 0x80;

    // clock_seq_low
    uuid[i++] = this.clockseq & 0xff;

    // node (48 bit)
    if (node.length !== 6) return;
    for (let n = 0; n < 6; n++) {
      uuid[i++] = node[n];
    }

    return uuid;
  }


  /**
   * Create a random based V4 UUID
   * @param {Uint8Array} rand 16 byte array of TRUE random data
   * @return {Uint8Array} UUID as 16 byte typed array or 'undefined' if error
   */
  v4(rand: Uint8Array) {
    if (rand.length !== 16) return;
    let uuid = new Uint8Array(rand);

    // set bits for version and clock_seq_hi_and_reserved
    uuid[6] = (uuid[6] & 0x0f) | 0x40;  // version is 'V4'
    uuid[8] = (uuid[8] & 0x3f) | 0x80;

    return uuid;
  }


  /**
   * Convert an UUID to string format like 550e8400-e29b-11d4-a716-446655440000
   * @param {Uint8Array} uuid 16 byte UUID as byte array
   * @return {String} UUID as string
   */
  toString(uuid: Uint8Array): string {
    if (uuid.length !== 16) return 'UUID format error';
    let i = 0, b2h = Convert.bin2hex;
    return b2h(uuid.subarray(i,++i)) + b2h(uuid.subarray(i,++i)) +
           b2h(uuid.subarray(i,++i)) + b2h(uuid.subarray(i,++i)) + '-' +
           b2h(uuid.subarray(i,++i)) + b2h(uuid.subarray(i,++i)) + '-' +
           b2h(uuid.subarray(i,++i)) + b2h(uuid.subarray(i,++i)) + '-' +
           b2h(uuid.subarray(i,++i)) + b2h(uuid.subarray(i,++i)) + '-' +
           b2h(uuid.subarray(i,++i)) + b2h(uuid.subarray(i,++i)) +
           b2h(uuid.subarray(i,++i)) + b2h(uuid.subarray(i,++i)) +
           b2h(uuid.subarray(i,++i)) + b2h(uuid.subarray(i,++i));
  }
}
