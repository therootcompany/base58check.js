(function (exports) {
  "use strict";

  // See also:
  // - https://en.bitcoin.it/wiki/Base58Check_encoding
  // - https://appdevtools.com/base58-encoder-decoder

  /** @type {import('crypto')} */
  //@ts-ignore
  let Crypto = exports.crypto || require("node:crypto");

  let BASE58 = `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`;

  let Base58Check = {};
  let BaseX = {};

  /**
   * @param {Object} [opts]
   * @param {String} [opts.pubKeyHashVersion] - "4c" for mainnet (default), "8c" for testnet, "00" for bitcoin
   * @param {String} [opts.privateKeyVersion] - "cc" for mainnet (default), "ef" for testnet, '80' for bitcoin
   * @param {String} [opts.dictionary] - "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for Dash / Bitcoin Base58
   */
  Base58Check.create = function (opts) {
    // See https://github.com/dashhive/dashkeys.js/blob/1f0f4e0d0aabf9e68d94925d660f00666f502391/dashkeys.js#L38
    let pubKeyHashVersion = opts?.pubKeyHashVersion || "4c";
    let privateKeyVersion = opts?.privateKeyVersion || "cc";
    let dictionary = opts?.dictionary || BASE58;

    let bs58 = BaseX.createEncoder(dictionary);
    let b58c = {};

    b58c.checksum = async function (parts) {
      let key = parts.pubKeyHash || parts.privateKey;
      if (parts.compressed && 64 === key.length) {
        key += "01";
      }
      let hex = `${parts.version}${key}`;
      let buf = hexToUint8Array(hex);
      let hash1 = await sha256sum(buf);
      let hash2 = await sha256sum(hash1);

      let check = uint8ArrayToHex(hash2.slice(0, 4));
      return check;
    };

    b58c.verify = async function (b58Addr) {
      let u8 = bs58.decode(b58Addr);
      let hex = uint8ArrayToHex(u8);
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
      let hex = uint8ArrayToHex(u8);
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
      let u8 = hexToUint8Array(hex);
      return bs58.encode(u8);
    };

    b58c.encodeHex = async function (parts) {
      let key = parts.pubKeyHash || parts.privateKey;
      let compressed = parts.compressed ?? true;

      if (40 === key.length) {
        if (!parts.version) {
          parts.version = pubKeyHashVersion || "00";
        }
        if (
          pubKeyHashVersion &&
          parts.version &&
          parts.version !== pubKeyHashVersion
        ) {
          throw new Error(
            "[@root/base58check] public key hash version mismatch"
          );
        }
      } else {
        if (66 === key.length && "01" === key.slice(-2)) {
          //key.slice(0, 64);
          compressed = true;
        } else if (64 === key.length && compressed) {
          key += "01";
        } else {
          throw new Error(
            `[@root/base58check] ${key.length} is not a valid key length, should be 66, 64, or 40 bytes`
          );
        }

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

  // base58 (base-x) encoding / decoding
  // Copyright (c) 2022 Dash Incubator (base58)
  // Copyright (c) 2021-2022 AJ ONeal (base62)
  // Copyright (c) 2018 base-x contributors
  // Copyright (c) 2014-2018 The Bitcoin Core developers (base58.cpp)
  // Distributed under the MIT software license, see the accompanying
  // file LICENSE or http://www.opensource.org/licenses/mit-license.php.
  //
  // Taken from https://github.com/therootcompany/base62.js
  // which is a fork of https://github.com/cryptocoinjs/base-x

  /**
   * @param {String} ALPHABET
   */
  BaseX.createEncoder = function (ALPHABET) {
    if (!ALPHABET) {
      ALPHABET = BASE58;
    }
    if (ALPHABET.length >= 255) {
      throw new TypeError("Alphabet too long");
    }

    var BASE_MAP = new Uint8Array(256);
    for (var j = 0; j < BASE_MAP.length; j += 1) {
      BASE_MAP[j] = 255;
    }
    for (var i = 0; i < ALPHABET.length; i += 1) {
      var x = ALPHABET.charAt(i);
      var xc = x.charCodeAt(0);
      if (BASE_MAP[xc] !== 255) {
        throw new TypeError(x + " is ambiguous");
      }
      BASE_MAP[xc] = i;
    }

    var BASE = ALPHABET.length;
    var LEADER = ALPHABET.charAt(0);
    var FACTOR = Math.log(BASE) / Math.log(256); // log(BASE) / log(256), rounded up
    var iFACTOR = Math.log(256) / Math.log(BASE); // log(256) / log(BASE), rounded up

    function encode(source) {
      if (Array.isArray(source) || !(source instanceof Uint8Array)) {
        source = Uint8Array.from(source);
      }
      if (!(source instanceof Uint8Array)) {
        throw new TypeError("Expected Uint8Array");
      }
      if (source.length === 0) {
        return "";
      }
      // Skip & count leading zeroes.
      var zeroes = 0;
      var length = 0;
      var pbegin = 0;
      var pend = source.length;
      while (pbegin !== pend && source[pbegin] === 0) {
        pbegin += 1;
        zeroes += 1;
      }
      // Allocate enough space in big-endian base58 representation.
      var size = ((pend - pbegin) * iFACTOR + 1) >>> 0;
      var b58 = new Uint8Array(size);
      // Process the bytes.
      while (pbegin !== pend) {
        var carry = source[pbegin];
        // Apply "b58 = b58 * 256 + ch".
        var i = 0;
        for (
          var it1 = size - 1;
          (carry !== 0 || i < length) && it1 !== -1;
          it1 -= 1, i += 1
        ) {
          carry += (256 * b58[it1]) >>> 0;
          b58[it1] = carry % BASE >>> 0;
          carry = (carry / BASE) >>> 0;
        }
        if (carry !== 0) {
          throw new Error("Non-zero carry");
        }
        length = i;
        pbegin += 1;
      }
      // Skip leading zeroes in base58 result.
      var it2 = size - length;
      while (it2 !== size && b58[it2] === 0) {
        it2 += 1;
      }
      // Translate the result into a string.
      var str = LEADER.repeat(zeroes);
      for (; it2 < size; it2 += 1) {
        str += ALPHABET.charAt(b58[it2]);
      }
      return str;
    }

    function decodeUnsafe(source) {
      if (typeof source !== "string") {
        throw new TypeError("Expected String");
      }
      if (source.length === 0) {
        return new Uint8Array(0);
      }
      var psz = 0;
      // Skip and count leading '1's.
      var zeroes = 0;
      var length = 0;
      while (source[psz] === LEADER) {
        zeroes += 1;
        psz += 1;
      }
      // Allocate enough space in big-endian base256 representation.
      var size = ((source.length - psz) * FACTOR + 1) >>> 0; // log(58) / log(256), rounded up.
      var b256 = new Uint8Array(size);
      // Process the characters.
      while (source[psz]) {
        // Decode character
        var carry = BASE_MAP[source.charCodeAt(psz)];
        // Invalid character
        if (carry === 255) {
          return;
        }
        var i = 0;
        for (
          var it3 = size - 1;
          (carry !== 0 || i < length) && it3 !== -1;
          it3 -= 1, i += 1
        ) {
          carry += (BASE * b256[it3]) >>> 0;
          b256[it3] = carry % 256 >>> 0;
          carry = (carry / 256) >>> 0;
        }
        if (carry !== 0) {
          throw new Error("Non-zero carry");
        }
        length = i;
        psz += 1;
      }
      // Skip leading zeroes in b256.
      var it4 = size - length;
      while (it4 !== size && b256[it4] === 0) {
        it4 += 1;
      }
      var vch = new Uint8Array(zeroes + (size - it4));
      var j = zeroes;
      while (it4 !== size) {
        vch[j] = b256[it4];
        j += 1;
        it4 += 1;
      }
      return vch;
    }

    function decode(string) {
      var buffer = decodeUnsafe(string);
      if (buffer) {
        return buffer;
      }
      throw new Error("Non-base" + BASE + " character");
    }

    return {
      encode: encode,
      decodeUnsafe: decodeUnsafe,
      decode: decode,
    };
  };

  /**
   * Hex to JS Buffer that works for Little-Endian CPUs (ARM, x64, x86, WASM)
   * @param {String} - hex
   * @returns {Buffer|Uint8Array} - buf
   */
  function hexToUint8Array(hex) {
    // TODO throw if not even
    let buf = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      let b = parseInt(hex[i] + hex[i + 1], 16);
      let index = i / 2;
      buf[index] = b;
    }

    return buf;
  }

  /**
   * @callback Sha256Sum
   * @param {Uint8Array|Buffer} u8
   * @returns {Promise<Uint8Array|Buffer>}
   */

  /** @type {Sha256Sum} */
  async function sha256sum(u8) {
    let arrayBuffer = await Crypto.subtle.digest("SHA-256", u8);
    let buf = new Uint8Array(arrayBuffer);
    return buf;
  }

  /**
   * JS Buffer to Hex that works for Little-Endian CPUs (ARM, x64, x86, WASM)
   * @param {Uint8Array} buf
   * @returns {String} - hex
   */
  function uint8ArrayToHex(buf) {
    /** @type {Array<String>} */
    let hex = [];

    buf.forEach(function (b) {
      let c = b.toString(16).padStart(2, "0");
      hex.push(c);
    });

    return hex.join("");
  }

  exports.Base58Check = Base58Check;
  exports.Base58 = BaseX;
  exports.BaseX = BaseX;
})(("undefined" !== typeof module && module.exports) || window);
