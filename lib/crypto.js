"use strict";

let NodeCrypto = require("crypto");

let Crypto = {};

Crypto.sha256 = async function (u8) {
  let buf = Buffer.from(u8);
  let hash = NodeCrypto.createHash(`sha256`).update(buf).digest();
  return new Uint8Array(hash);
};

exports.Crypto = Crypto;
