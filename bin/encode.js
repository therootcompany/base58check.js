#!/usr/bin/env node
"use strict";

var Base58Check = require("../base58check.js").Base58Check;

async function main() {
  let b58c = Base58Check.create();
  let key = process.argv[2];
  let version = process.argv[3];

  if (!key || ["help", "-h", "--help"].includes(key)) {
    console.error("Usage: encode <key> <version>");
    process.exit(1);
    return;
  }

  let compressed;
  let pubKeyHash;
  let privateKey;
  if (40 === key.length) {
    pubKeyHash = key;
    if (!version) {
      version = "00"; // 4c for Dash
    }
  } else {
    privateKey = key;
    if (!key.slice(64) || "01" === key.slice(64)) {
      compressed = true;
    }
    if (!version) {
      version = "80"; // cc for Dash
    }
  }

  let opts = {
    version,
    pubKeyHash,
    privateKey,
    compressed,
  };
  let addrOrKey = await b58c.encode(opts);
  console.info(JSON.stringify(opts, null, 2));
  console.info(addrOrKey);
}

main().catch(function (err) {
  console.error("Fail:");
  console.error(err.stack || err);
});
