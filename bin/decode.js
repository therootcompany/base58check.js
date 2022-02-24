#!/usr/bin/env node
"use strict";

var Base58Check = require("../base58check.js").Base58Check;

async function main() {
  let b58c = Base58Check.create();
  let key = process.argv[2];
  if (!key || ["help", "-h", "--help"].includes(key)) {
    console.error("Usage: decode <key>");
    process.exit(1);
    return;
  }

  var parts = await b58c.verify(key);
  console.info(key);
  console.info(JSON.stringify(parts, null, 2));
}

main().catch(function (err) {
  console.error("Fail:");
  console.error(err.stack || err);
});
