"use strict";

const BASE58 = `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`;

let Base58Check = require("./base58check.js");

let bs58 = require(`base-x`)(BASE58);

let b58c = Base58Check.create({
  pubKeyHashVersion: "4c",
  privateKeyVersion: "cc",
  // TODO allow changing dicitonary
});

function toWif() {
  [
    // generated with dashcore
    "XJQSCYgjEvXzDNj5QUSn1jxspgSJtBZ9Mtp5gHZ3cBrdMj2FYdxU",
    "XBnGvT9GP1LsXNC3mXHmKx544FaY4kBQzSYUQ77X2P17AaVgQbYv",
    "XFShaP4gGuXohTW4VGTaTvRptmhbsi7PPJuQpTjDouzC2yjVU4yT",
    "XFPzxuhx4hW75uyJKRczmk88EUqeQsTHP1xngXXPKWrwhoineRLL",
    "XFtVTxMFh1Ls1ySfg1TPVZCYswaJuuMx3CTar1XcfN5NceysSRqA",
    "XJLDiUFwgFTi6CcjJFiJUCHJGfsfhSUgZ8jgyPm2AhPfDaTS21gm",
    "XDgzfzNmKvbHk71EVpjUB6LDqWa8Pq88baD6iUo4oBzcekfL3Fdz",
    "XE79AWSyEb1TdKSbbRVnEMCRp8kfK5iX1CdbmPkPNkWfCWZ3AQpz",
    "XFPxuUn5Epz625e6FXAVXL5W8C87iLc8q8KK8ioexsU8dwj9RidW",
    "XFdqUukoCypRmmSrVWCZm5gFC7DGKNByHr66DmVL6JZTEPzmkoog",
    "XCBPnETeYM3CESgw94wM19u6qR4YWkokHB9MuCD4faTMbVeBRkmT",
  ].forEach(function (prv) {
    b58c.verifyPrivate(prv);
  });
}

function toPubKeyHash() {
  let reference = `Xd5GzCN6mp77BeVEe6FrgqQt8MA1ge4Fsw`;
  let hex = `4c 1a2e668007a28dbecb420a8e9ce8cdd1651f213d 6496ad2a`;
  hex = hex.replace(/\s*/g, ``);

  let bufAddr = Buffer.from(hex, `hex`);
  let addr = bs58.encode(bufAddr);
  if (addr !== reference) {
    throw new Error(
      "[SANITY FAIL] the universe no longer obeys the law of base58"
    );
  }

  let parts = b58c.verify(addr);
  console.info(`\t` + JSON.stringify(parts));

  let full = b58c.encode(parts);
  console.info(`\t${full}`);

  if (full !== addr) {
    throw new Error(`expected '${addr}' but got '${full}'`);
  }
}

console.info("");
console.info("To WIF...");
toWif();
console.info(`PASS`);

console.info("");
console.info(`To PubKeyHash...`);
toPubKeyHash();
console.info(`PASS`);

console.info("");
