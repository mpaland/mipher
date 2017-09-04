global.btoa = function (str) {
  return new Buffer(str).toString('base64');
};

global.atob = function (b64) {
  return new Buffer(b64, 'base64').toString();
};

// global.chai = require('chai');
// var expect = chai.expect;
// var assert = chai.assert;
