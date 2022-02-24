(function (exports) {
  "use strict";

  let Crypto = {};

  let crypto = window.crypto;

  Crypto.sha256 = async function (u8) {
    let ab = await crypto.subtle.digest({ name: "SHA-256" }, u8.buffer);

    return new Uint8Array(ab);
  };

  exports.Crypto = Crypto;
})(("undefined" === typeof module && window) || module.exports);
