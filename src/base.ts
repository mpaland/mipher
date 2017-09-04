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
// \brief mipher convert and util functions
//
///////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
// V E R S I O N

export const version = "1.0.0";


///////////////////////////////////////////////////////////////////////////////
// I N T E R F A C E S

export interface Blockcipher {
  blockSize: number;
  encrypt(key: Uint8Array, pt: Uint8Array): Uint8Array;
  decrypt(key: Uint8Array, ct: Uint8Array): Uint8Array;
  selftest(): boolean;
}

export interface Streamcipher {
  encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
  decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
  selftest(): boolean;
}

export interface PublicKey {
  generateKeys(seed: Uint8Array): { sk: Uint8Array, pk: Uint8Array };
  encrypt(pk: Uint8Array, pt: Uint8Array): Uint8Array;
  decrypt(sk: Uint8Array, ct: Uint8Array): Uint8Array;
  selftest(): boolean;
}

export interface Signature {
  generateKeys(seed: Uint8Array): { sk: Uint8Array, pk: Uint8Array };
  sign(msg: Uint8Array, sk: Uint8Array, pk: Uint8Array): Uint8Array;
  verify(msg: Uint8Array, pk: Uint8Array, sig: Uint8Array): boolean;
  selftest(): boolean;
}

export interface Hash {
  hashSize: number;
  init(): Hash;
  update(msg?: Uint8Array): Hash;
  digest(msg?: Uint8Array): Uint8Array;
  hash(msg?: Uint8Array): Uint8Array;
  selftest(): boolean;
}

export interface KeyedHash {
  hashSize: number;
  init(key: Uint8Array): KeyedHash;
  update(msg?: Uint8Array): KeyedHash;
  digest(msg?: Uint8Array): Uint8Array;
  hash(key: Uint8Array, msg?: Uint8Array): Uint8Array;
  selftest(): boolean;
}


///////////////////////////////////////////////////////////////////////////////
// C O N V E R T E R

export namespace Convert {

  /**
   * Convert a string (UTF-8 encoded) to a byte array
   * @param {String} str UTF-8 encoded string
   * @return {Uint8Array} Byte array
   */
  export function str2bin(str: string): Uint8Array {
    str = str.replace(/\r\n/g, '\n');
    let bin = new Uint8Array(str.length * 3), p = 0;
    for (let i = 0, len = str.length; i < len; i++) {
      let c = str.charCodeAt(i);
      if (c < 128) {
        bin[p++] = c;
      } else if (c < 2048) {
        bin[p++] = (c >>> 6) | 192;
        bin[p++] = (c & 63) | 128;
      } else {
        bin[p++] = (c >>> 12) | 224;
        bin[p++] = ((c >>> 6) & 63) | 128;
        bin[p++] = (c & 63) | 128;
      }
    }
    return bin.subarray(0, p);
  }


  /**
   * Convert a hex string to byte array
   * @param {String} hex Hex string
   * @return {Uint8Array} Byte array
   */
  export function hex2bin(hex: string): Uint8Array {
    if (hex.indexOf('0x') === 0 || hex.indexOf('0X') === 0) {
      hex = hex.substr(2);
    }
    if (hex.length % 2) {
      hex += '0';
    }

    let bin = new Uint8Array(hex.length >>> 1);
    for (let i = 0, len = hex.length >>> 1; i < len; i++) {
      bin[i] = parseInt(hex.substr(i << 1, 2), 16);
    }
    return bin;
  }


  /**
   * Convert a 32 bit integer number to a 4 byte array, LSB is first
   * @param {Number} integer Integer number
   * @return {Uint8Array} bin 4 byte array
   */
  export function int2bin(integer: number): Uint8Array {
    let bin = new Uint8Array(4);
    bin[0] = (integer)        & 0xff;
    bin[1] = (integer >>>  8) & 0xff;
    bin[2] = (integer >>> 16) & 0xff;
    bin[3] = (integer >>> 24) & 0xff;
    return bin;
  }


  /**
   * Convert a number to a 8 byte array, LSB is first
   * @param {Number} value Long number
   * @return {Uint8Array} bin 8 byte array
   */
  export function number2bin(value: number): Uint8Array {
    let bin = new Uint8Array(8);
    if (Math.floor(value) === value) {
      const TWO_PWR_32 = 4294967296;
      let lo = (value % TWO_PWR_32) | 0, hi = (value / TWO_PWR_32) | 0;
      if (value < 0) {
        lo = ~(-value % TWO_PWR_32) | 0, hi = ~(-value / TWO_PWR_32) | 0;
        lo = (lo + 1) & 0xffffffff;
        if (!lo) hi++;
      }
      let i = 0;
      bin[i++] = (lo & 0xff); bin[i++] = (lo >>> 8) & 0xff; bin[i++] = (lo >>> 16) & 0xff; bin[i++] = (lo >>> 24) & 0xff;
      bin[i++] = (hi & 0xff); bin[i++] = (hi >>> 8) & 0xff; bin[i++] = (hi >>> 16) & 0xff; bin[i]   = (hi >>> 24) & 0xff;
    }
    else {    // it's a float / double
      var f = new Float64Array([value]);
      var d = new Uint8Array(f.buffer);
      bin.set(d);
    }
    return bin;
  }


  /**
   * Convert a base64/base64url string to a byte array
   * @param {String} base64 Base64/Base64url encoded string
   * @return {Uint8Array} Byte array or undefined if error
   */
  export function base642bin(base64: string): Uint8Array {
    // remove base64url encoding
    base64 = base64.replace(/-/g, '+').replace(/_/g, '/').replace(/%3d/g, '=');
    // length must be multiple of 4
    if (base64.length % 4 !== 0) return;

    let strlen = base64.length / 4 * 3;
    if (base64.charAt(base64.length - 1) === '=') strlen--;
    if (base64.charAt(base64.length - 2) === '=') strlen--;

    if (typeof atob !== 'undefined') {
      return new Uint8Array(atob(base64).split('').map(function (c) { return c.charCodeAt(0); }));
    }
    else {
      // atob not available
      const decodingTable = new Int8Array([
        -1, -1, -1, -1, -1, -1, -1, -1,   // . . . .  . . . .
        -1, -1, -1, -1, -1, -1, -1, -1,   // . . . .  . . . .
        -1, -1, -1, -1, -1, -1, -1, -1,   // . . . .  . . . .
        -1, -1, -1, -1, -1, -1, -1, -1,   // . . . .  . . . .
        -1, -1, -1, -1, -1, -1, -1, -1,   // . . . .  . . . .
        -1, -1, -1, 62, -1, 62, -1, 63,   // . . . +  . - . /
        52, 53, 54, 55, 56, 57, 58, 59,   // 0 1 2 3  4 5 6 7
        60, 61, -1, -1, -1, -2, -1, -1,   // 8 9 . .  . = . .
        -1,  0,  1,  2,  3,  4,  5,  6,   // . A B C  D E F G
        7,   8,  9, 10, 11, 12, 13, 14,   // H I J K  L M N O
        15, 16, 17, 18, 19, 20, 21, 22,   // P Q R S  T U V W
        23, 24, 25, -1, -1, -1, -1, 63,   // X Y Z .  . . . _
        -1, 26, 27, 28, 29, 30, 31, 32,   // . a b c  d e f g
        33, 34, 35, 36, 37, 38, 39, 40,   // h i j k  l m n o
        41, 42, 43, 44, 45, 46, 47, 48,   // p q r s  t u v w
        49, 50, 51, -1, -1, -1, -1, -1    // x y z .  . . . .
      ]);

      let p = 0, bin = new Uint8Array(strlen);
      for (let i = 0, len = base64.length; i < len;) {
        let sextet_a = base64.charAt(i) === '=' || base64.charCodeAt(i) > 'z'.charCodeAt(0) ? 0 : decodingTable[base64.charCodeAt(i)]; i++;
        let sextet_b = base64.charAt(i) === '=' || base64.charCodeAt(i) > 'z'.charCodeAt(0) ? 0 : decodingTable[base64.charCodeAt(i)]; i++;
        let sextet_c = base64.charAt(i) === '=' || base64.charCodeAt(i) > 'z'.charCodeAt(0) ? 0 : decodingTable[base64.charCodeAt(i)]; i++;
        let sextet_d = base64.charAt(i) === '=' || base64.charCodeAt(i) > 'z'.charCodeAt(0) ? 0 : decodingTable[base64.charCodeAt(i)]; i++;
        let triple = (sextet_a << 18) +
                     (sextet_b << 12) +
                     (sextet_c <<  6) +
                     (sextet_d);
        if (base64.charAt(i - 3) !== '=') bin[p++] = (triple >>> 16) & 0xff;
        if (base64.charAt(i - 2) !== '=') bin[p++] = (triple >>>  8) & 0xff;
        if (base64.charAt(i - 1) !== '=') bin[p++] = (triple)        & 0xff;
      }
      return bin;
    }
  }


  /**
   * Convert a byte array to hex string
   * @param {Uint8Array} bin The input byte array
   * @param {Boolean} uppercase True for upper case hex numbers
   * @return {String} Hex sting
   */
  export function bin2hex(bin: Uint8Array, uppercase: boolean = false): string {
    let hex = uppercase ? '0123456789ABCDEF' : '0123456789abcdef';
    let str = '';
    for (let i = 0, len = bin.length; i < len; i++) {
      str += hex.charAt((bin[i] >>> 4) & 0x0f) + hex.charAt(bin[i] & 0x0f);
      // str += bin[i].toString(16);
    }
    return str;
  }


  /**
   * Convert a byte array to string (UTF-8 dedode)
   * @param {Uint8Array} bin UTF-8 text given as array of bytes
   * @return {String} UTF-8 Text string
   */
  export function bin2str(bin: Uint8Array): string {
    let str = '', len = bin.length, i = 0, c, c2, c3;

    while (i < len) {
      c = bin[i];
      if (c < 128) {
        str += String.fromCharCode(c);
        i++;
      }
      else if ((c > 191) && (c < 224)) {
        c2 = bin[i + 1];
        str += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
        i += 2;
      }
      else {
        c2 = bin[i + 1];
        c3 = bin[i + 2];
        str += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
        i += 3;
      }
    }
    return str;
  }


  /**
   * Convert a byte value array in a long value array
   * @param {Uint8Array} bin Array of bytes
   * @return {Uint32Array} bin values in long format
   */
  export function bin2longbin(bin: Uint8Array): Uint32Array {
    let longbin = new Uint32Array(bin.length >>> 2);
    for (let i = 0, len = bin.length; i < len; i++) {
      longbin[i >>> 2] |= (bin[i] << ((i % 4) << 3));
    }
    return longbin;
  }


  /**
   * Convert a 8 byte (int64) array into a number
   * @param {Uint8Array} bin Array of 8 bytes (int64), LSB is [0], MSB is [7]
   * @return {Number} int64 value as number
   */
  export function bin2number(bin: Uint8Array): number {
    const TWO_PWR_32 = 4294967296;
    let i = 0;
    let lo = bin[i++] | bin[i++] << 8 | bin[i++] << 16 | bin[i++] << 24;
    let hi = bin[i++] | bin[i++] << 8 | bin[i++] << 16 | bin[i]   << 24;
    return hi * TWO_PWR_32 + ((lo >= 0) ? lo : TWO_PWR_32 + lo);
  }


  /**
   * Convert byte array to base64/base64url string
   * @param {Uint8Array} bin Array of bytes
   * @param {Boolean} url True if the string should be URL encoded (base64url encoding)
   * @return {String} Base64 encoded string
   */
  export function bin2base64(bin: Uint8Array, url: boolean = false): string {
    if (typeof btoa !== 'undefined') {
      return url ? btoa(String.fromCharCode.apply(null, bin)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '%3d') :
                   btoa(String.fromCharCode.apply(null, bin));
    }
    else {
      // btoa not available
      let base64 = '',
        encodingTable = url ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' :
                              'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      for (let i = 0, len = bin.length; i < len;) {
        let octet_a = i < bin.length ? bin[i] : 0; i++;
        let octet_b = i < bin.length ? bin[i] : 0; i++;
        let octet_c = i < bin.length ? bin[i] : 0; i++;
        let triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        base64 += encodingTable.charAt((triple >>> 18) & 0x3F);
        base64 += encodingTable.charAt((triple >>> 12) & 0x3F);
        base64 += (i < bin.length + 2) ? encodingTable.charAt((triple >>> 6) & 0x3F) : (url ? '%3d' : '=');
        base64 += (i < bin.length + 1) ? encodingTable.charAt((triple >>> 0) & 0x3F) : (url ? '%3d' : '=');
      }
      return base64;
    }
  }
}


///////////////////////////////////////////////////////////////////////////////
// U T I L S

export namespace Util {

  /**
   * Time constant comparison of two arrays
   * @param {Uint8Array} lh First array of bytes
   * @param {Uint8Array} rh Second array of bytes
   * @return {Boolean} True if the arrays are equal (length and content), false otherwise
   */
  export function compare(lh: Uint8Array, rh: Uint8Array): boolean {
    if (lh.length !== rh.length) {
      // abort
      return false;
    }
    let r = true;
    for (let i = 0, len = lh.length; i < len; i++) {
      r = r && (lh[i] === rh[i]);
    }
    return r;
  }


  /**
   * XOR two arrays and return the result array
   * @param {Uint8Array} lh First array of bytes
   * @param {Uint8Array} rh Second array of bytes
   * @return {Uint8Array} XORed result array
   */
  export function xor(lh: Uint8Array, rh: Uint8Array): Uint8Array {
    let x = new Uint8Array(lh.length);
    for (let i = 0, len = lh.length; i < len; i++) {
      x[i] = lh[i] ^ rh[i];
    }
    return x;
  }


  /**
   * Concat two arrays and returns a new result array
   * @param {Uint8Array} lh First array of bytes
   * @param {Uint8Array} rh Second array of bytes
   * @return {Uint8Array} Concatenated result array
   */
  export function concat(lh: Uint8Array, rh: Uint8Array): Uint8Array {
    let x = new Uint8Array(lh.length + rh.length);
    x.set(lh, 0);
    x.set(rh, lh.length);
    return x;
  }


  /**
   * Returns true if LITTLE endian is detected
   * @return {Boolean} True for LE, false for BE
   */
  export function litteendian(): boolean {
    return (new Uint32Array((new Uint8Array([1, 2, 3, 4])).buffer))[0] === 0x04030201;
  }
}
