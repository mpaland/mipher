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
// \brief padding modes implementation
//
///////////////////////////////////////////////////////////////////////////////

export class PKCS7 {
  /**
   * PKCS#7 padding function. Pads bytes to given text until text is multiple of blocksize is met
   * @param {Uint8Array} bin Byte array where the bytes are padded
   * @param {Number} blocksize The blocksize in bytes of the text to which the text should be padded
   * @return {Uint8Array} Padded byte array
   */
  pad(bin: Uint8Array, blocksize: number): Uint8Array {
    let len = bin.length % blocksize ? blocksize - (bin.length % blocksize) : blocksize;
    let out = new Uint8Array(bin.length + len);
    out.set(bin, 0);
    for (let i = bin.length, l = bin.length + len; i < l; ++i) {
      out[i] = len;
    }
    return out;
  }

  /**
   * PKCS#7 stripping function. Strips bytes of the given text
   * @param {Uint8Array} bin Byte array where the bytes are stripped
   * @return {Uint8Array} Stripped byte array
   */
  strip(bin: Uint8Array): Uint8Array {
    return bin.subarray(0, bin.length - bin[bin.length - 1]);
  }
}

///////////////////////////////////////////////////////////////////////////////

export class PKCS5 {
  pkcs7: PKCS7;

  /**
   * PKCS#5 ctor
   */
  constructor() {
    this.pkcs7 = new PKCS7();
  }

  /**
   * PKCS#5 padding function. Pads bytes to given text until text is multiple of 8
   * @param {Uint8Array} bin Byte array where the bytes are padded
   * @return {Uint8Array} Padded byte array
   */
  pad(bin: Uint8Array): Uint8Array {
    return this.pkcs7.pad(bin, 8);
  }

  /**
   * PKCS#5 stripping function. Strips bytes of the given text
   * @param {Uint8Array} bin Byte array where the bytes are stripped
   * @return {Uint8Array} Stripped byte array
   */
  strip(bin: Uint8Array): Uint8Array {
    return this.pkcs7.strip(bin);
  }
}

///////////////////////////////////////////////////////////////////////////////

export class ZeroPadding {
  /**
   * Pads zero bytes to the given array until the length is a multiple of blocksize
   * @param {Uint8Array} bin The text where the zero bytes are padded
   * @param {Number} blocksize The blocksize to which the array should be padded
   * @return {Uint8Array} Padded byte array
   */
  pad(bin: Uint8Array, blocksize: number): Uint8Array {
    if (bin.length % blocksize === 0) return;
    let out = new Uint8Array(blocksize);
    out.set(bin, 0);
    return out;
  }

  /**
   * Zero stripping function. Just a dummy
   * @param {Array} bin Byte array where the bytes are stripped
   */
  strip(bin: Uint8Array): Uint8Array {
    return bin;
  }
}
