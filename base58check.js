"use strict";

// See also:
// - https://en.bitcoin.it/wiki/Base58Check_encoding
// - https://appdevtools.com/base58-encoder-decoder

let Base58Check = module.exports;

const BASE58 = `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`;

let Crypto = require(`crypto`);

let bs58 = require(`base-x`)(BASE58);

//let dashPubVersion = `4c`; // 00
//let dashPrvVersion = `cc`; // 80

function u8ToHex(u8) {
  let hexArr = [];
  u8.forEach(function (n) {
    hexArr.push(n.toString(16).padStart(2, "0"));
  });
  let hex = hexArr.join("");
  return hex;
}

Base58Check.create = function ({ pubKeyHashVersion, privateKeyVersion }) {
  let b58c = {};

  b58c.checksum = function (parts) {
    let key = parts.pubKeyHash || parts.privateKey;
    if (parts.compressed) {
      key += "01";
    }
    let buf = Buffer.from(`${parts.version}${key}`, `hex`);
    let hash1 = Crypto.createHash(`sha256`).update(buf).digest();
    let hash2 = Crypto.createHash(`sha256`).update(hash1).digest(`hex`);
    let check = hash2.slice(0, 8);

    return check;
  };

  b58c.verify = function (b58Addr) {
    let u8 = bs58.decode(b58Addr);
    let hex = u8ToHex(u8);
    return b58c.verifyHex(hex);
  };

  b58c.verifyPrivate = function (b58Addr) {
    let u8 = bs58.decode(b58Addr);
    let hex = u8ToHex(u8);
    return b58c.verifyHex(hex, {
      length: 76,
    });
  };

  b58c.verifyHex = function (base58check, opts) {
    let parts = b58c.decodeHex(base58check, opts);
    let check = b58c.checksum(parts);

    if (parts.check !== check) {
      throw new Error(`expected '${parts.check}', but got '${check}'`);
    }

    return parts;
  };

  b58c.decode = function (b58Addr) {
    let u8 = bs58.decode(b58Addr);
    let hex = u8ToHex(u8);
    return b58c.decodeHex(hex, {
      length: 50,
    });
  };

  b58c.decodePrivate = function (b58Addr) {
    let u8 = bs58.decode(b58Addr);
    let hex = u8ToHex(u8);
    return b58c.decodeHex(hex, {
      length: 76,
    });
  };

  // decode b58c
  b58c.decodeHex = function (addr, opts = {}) {
    let length = opts?.length || 50;
    if (length !== addr.length) {
      console.log(addr);
      throw new Error(
        `pubKeyHash (or privateKey) isn't as long as expected (should be ${length} chars, not ${addr.length})`
      );
    }

    let version = addr.slice(0, 2);
    if (![pubKeyHashVersion, privateKeyVersion].includes(version)) {
      throw new Error(
        `expected Dash pubKeyHash (or privateKey) to start with 0x4c (or 0xcc), not '0x${version}'`
      );
    }

    let rawAddr = addr.slice(2, -8);
    if (50 === length) {
      return {
        version,
        pubKeyHash: rawAddr,
        check: addr.slice(-8),
      };
    }
    return {
      version,
      privateKey: rawAddr.slice(0, 64),
      compressed: "01" === rawAddr.slice(64),
      check: addr.slice(-8),
    };
  };

  b58c.encode = function (parts) {
    let hex = b58c.encodeHex(parts);
    let buf = Buffer.from(hex, `hex`);
    return bs58.encode(Array.from(buf));
  };

  b58c.encodeHex = function (parts) {
    let check = b58c.checksum(parts);
    let key = parts.pubKeyHash || parts.privateKey;
    if (parts.compressed) {
      key += "01";
    }
    return `${parts.version}${key}${check}`;
  };

  return b58c;
};
