#!/usr/bin/env node
"use strict";

function main() {
  let key = process.argv[2];

  if ([40, 64, 66].includes(key.length)) {
    require("./encode.js");
    return;
  }
  require("./decode.js");
}

main();
