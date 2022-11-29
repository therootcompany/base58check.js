"use strict";

// See also:
// - https://en.bitcoin.it/wiki/Base58Check_encoding
// - https://appdevtools.com/base58-encoder-decoder

let Base58Check = {};

const BASE58 = `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`;

let Crypto = require("./lib/crypto.js").Crypto;

let BaseX = require("base-x");

Base58Check.create = function (opts) {
  let pubKeyHashVersion = opts?.pubKeyHashVersion;
  let privateKeyVersion = opts?.privateKeyVersion;
  let dictionary = opts?.dictionary;

  if (!dictionary) {
    dictionary = BASE58;
  }

  let bs58 = BaseX(dictionary);
  let b58c = {};

  b58c.checksum = async function (parts) {
    let key = parts.pubKeyHash || parts.privateKey;
    if (parts.compressed && 64 === key.length) {
      key += "01";
    }
    let buf = Buffer.from(`${parts.version}${key}`, `hex`);
    // TODO provide browser version as well
    let hash1 = await Crypto.sha256(buf);
    let hash2 = await Crypto.sha256(hash1);
    let hex = [];
    hash2.slice(0, 4).forEach(function (n) {
      hex.push(n.toString(16).padStart(2, "0"));
    });

    let check = hex.join("");
    return check;
  };

  b58c.verify = async function (b58Addr) {
    let u8 = bs58.decode(b58Addr);
    let hex = u8ToHex(u8);
    return await b58c.verifyHex(hex);
  };

  b58c.verifyHex = async function (base58check, opts) {
    let parts = b58c.decodeHex(base58check, opts);
    let check = await b58c.checksum(parts);

    if (parts.check !== check) {
      throw new Error(`expected '${parts.check}', but got '${check}'`);
    }

    return parts;
  };

  b58c.decode = function (b58Addr) {
    let u8 = bs58.decode(b58Addr);
    let hex = u8ToHex(u8);
    return b58c.decodeHex(hex);
  };

  // decode b58c
  b58c.decodeHex = function (addr, opts = {}) {
    // Public Key Hash: 1 + 20 + 4 // 50 hex
    // Private Key: 1 + 32 + 1 + 4 // 74 or 76 hex
    if (![50, 74, 76].includes(addr.length)) {
      throw new Error(
        `pubKeyHash (or privateKey) isn't as long as expected (should be 50, 74, or 76 hex chars, not ${addr.length})`
      );
    }

    let version = addr.slice(0, 2);
    let versions = [pubKeyHashVersion, privateKeyVersion].filter(Boolean);
    if (versions.length && !versions.includes(version)) {
      throw new Error(
        `expected Dash pubKeyHash (or privateKey) to start with 0x${pubKeyHashVersion} (or 0x${privateKeyVersion}), not '0x${version}'`
      );
    }

    let rawAddr = addr.slice(2, -8);
    if (50 === addr.length) {
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

  b58c.encode = async function (parts) {
    let hex = await b58c.encodeHex(parts);
    let u8 = hexToU8(hex);
    return bs58.encode(u8);
  };

  b58c.encodeHex = async function (parts) {
    let key = parts.pubKeyHash || parts.privateKey;
    let compressed = parts.compressed ?? true;

    if (66 === key.length && "01" === key.slice(-2)) {
      key.slice(0, 64);
      compressed = true;
    }

    if (64 === key.length && compressed) {
      key += "01";
    }

    if (40 === key.length) {
      if (!parts.version) {
        parts.version = pubKeyHashVersion || "00";
      }
      if (
        pubKeyHashVersion &&
        parts.version &&
        parts.version !== pubKeyHashVersion
      ) {
        throw new Error("[@root/base58check] public key hash version mismatch");
      }
    } else {
      if (!parts.version) {
        parts.version = privateKeyVersion || "80";
      }
      if (
        privateKeyVersion &&
        parts.version &&
        parts.version !== privateKeyVersion
      ) {
        throw new Error("[@root/base58check] private key version mismatch");
      }
    }

    // after version is set
    let check = await b58c.checksum(parts);

    return `${parts.version}${key}${check}`;
  };

  return b58c;
};

function hexToU8(hex) {
  let u8 = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    let n = parseInt(hex[i] + hex[i + 1], 16);
    u8[i / 2] = n;
  }
  return u8;
}

function u8ToHex(u8) {
  let hexArr = [];
  u8.forEach(function (n) {
    hexArr.push(n.toString(16).padStart(2, "0"));
  });
  let hex = hexArr.join("");
  return hex;
}

exports.Base58Check = Base58Check;
