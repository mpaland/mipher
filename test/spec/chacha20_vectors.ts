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
// \brief chacha20 test vectors
// TestVectors are taken from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#page-11
// and from https://tools.ietf.org/html/rfc7539
// pt is an array with the same length as ct and all values are '0', if not given
// ibc (Initial Block Counter) is 0 if not given
///////////////////////////////////////////////////////////////////////////////


interface vector_type {
  key: string;
  iv:  string;
  ct:  string;
  pt?: string;
  ibc?: number;
};

export const vector: vector_type[] = [
  {
    key: '0000000000000000000000000000000000000000000000000000000000000000',
    iv:  '0000000000000000',
    ct:  '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586'
  },
  {
    key: '0000000000000000000000000000000000000000000000000000000000000001',
    iv:  '0000000000000000',
    ct:  '4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963'
  },
  {
    key: '0000000000000000000000000000000000000000000000000000000000000000',
    iv:  '0000000000000001',
    ct:  'de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3'
  },
  {
    key: '0000000000000000000000000000000000000000000000000000000000000000',
    iv:  '0000000000000002',
    ct:  'c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d'
  },
  {
    key: '0000000000000000000000000000000000000000000000000000000000000000',
    iv:  '0100000000000000',
    ct:  'ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b'
  },
  {
    key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    iv:  '0001020304050607',
    ct:  'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56' +
         'f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f1' +
         '5916155c2be8241a38008b9a26bc35941e2444177c8ade6689de9526' +
         '4986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e' +
         '09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a4750' +
         '32b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c5' +
         '07b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f7' +
         '6dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2' +
         'ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab7' +
         '8fab78c9'
  },
  {
    key: '0000000000000000000000000000000000000000000000000000000000000001',
    iv:  '0000000000000002',
    ibc: 1,
    pt:  '416e79207375626d697373696f6e2074' +
         '6f20746865204945544620696e74656e' +
         '6465642062792074686520436f6e7472' +
         '696275746f7220666f72207075626c69' +
         '636174696f6e20617320616c6c206f72' +
         '2070617274206f6620616e2049455446' +
         '20496e7465726e65742d447261667420' +
         '6f722052464320616e6420616e792073' +
         '746174656d656e74206d616465207769' +
         '7468696e2074686520636f6e74657874' +
         '206f6620616e20494554462061637469' +
         '7669747920697320636f6e7369646572' +
         '656420616e20224945544620436f6e74' +
         '7269627574696f6e222e205375636820' +
         '73746174656d656e747320696e636c75' +
         '6465206f72616c2073746174656d656e' +
         '747320696e2049455446207365737369' +
         '6f6e732c2061732077656c6c20617320' +
         '7772697474656e20616e6420656c6563' +
         '74726f6e696320636f6d6d756e696361' +
         '74696f6e73206d61646520617420616e' +
         '792074696d65206f7220706c6163652c' +
         '20776869636820617265206164647265' +
         '7373656420746f',
    ct:  'a3fbf07df3fa2fde4f376ca23e827370' +
         '41605d9f4f4f57bd8cff2c1d4b7955ec' +
         '2a97948bd3722915c8f3d337f7d37005' +
         '0e9e96d647b7c39f56e031ca5eb6250d' +
         '4042e02785ececfa4b4bb5e8ead0440e' +
         '20b6e8db09d881a7c6132f420e527950' +
         '42bdfa7773d8a9051447b3291ce1411c' +
         '680465552aa6c405b7764d5e87bea85a' +
         'd00f8449ed8f72d0d662ab052691ca66' +
         '424bc86d2df80ea41f43abf937d3259d' +
         'c4b2d0dfb48a6c9139ddd7f76966e928' +
         'e635553ba76c5c879d7b35d49eb2e62b' +
         '0871cdac638939e25e8a1e0ef9d5280f' +
         'a8ca328b351c3c765989cbcf3daa8b6c' +
         'cc3aaf9f3979c92b3720fc88dc95ed84' +
         'a1be059c6499b9fda236e7e818b04b0b' +
         'c39c1e876b193bfe5569753f88128cc0' +
         '8aaa9b63d1a16f80ef2554d7189c411f' +
         '5869ca52c5b83fa36ff216b9c1d30062' +
         'bebcfd2dc5bce0911934fda79a86f6e6' +
         '98ced759c3ff9b6477338f3da4f9cd85' +
         '14ea9982ccafb341b2384dd902f3d1ab' +
         '7ac61dd29c6f21ba5b862f3730e37cfd' +
         'c4fd806c22f221'
  },
  {
    key: '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0',
    iv:  '0000000000000002',
    ibc: 42,
    pt:  '2754776173206272696c6c69672c2061' +
         '6e642074686520736c6974687920746f' +
         '7665730a446964206779726520616e64' +
         '2067696d626c6520696e207468652077' +
         '6162653a0a416c6c206d696d73792077' +
         '6572652074686520626f726f676f7665' +
         '732c0a416e6420746865206d6f6d6520' +
         '7261746873206f757467726162652e',
    ct:  '62e6347f95ed87a45ffae7426f27a1df' +
         '5fb69110044c0d73118effa95b01e5cf' +
         '166d3df2d721caf9b21e5fb14c616871' +
         'fd84c54f9d65b283196c7fe4f60553eb' +
         'f39c6402c42234e32a356b3e764312a6' +
         '1a5532055716ead6962568f87d3f3f77' +
         '04c6a8d1bcd1bf4d50d6154b6da731b1' +
         '87b58dfd728afa36757a797ac188d1'  
  }
];
