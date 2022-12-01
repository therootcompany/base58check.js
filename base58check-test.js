"use strict";

const BASE58 = `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`;

let Base58Check = require("./base58check.js").Base58Check;

let bs58 = require(`base-x`)(BASE58);

let b58c = Base58Check.create({
  pubKeyHashVersion: "4c",
  privateKeyVersion: "cc",
  // TODO allow changing dicitonary
});

async function toWif() {
  await [
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
  ].reduce(async function (prev, wif) {
    await b58c.verify(wif);

    let decoded = await b58c.decode(wif);
    let check = await b58c.checksum({
      privateKey: decoded.privateKey,
    });

    try {
      await b58c.checksum({
        pubKeyHash: decoded.privateKey,
      });
      throw new Error("allowed checksum of wrong key type");
    } catch (e) {
      // ignore, expected
    }

    if (decoded.check !== check) {
      throw new Error("checksum({ privateKey }) failed");
    }

    let encoded = await b58c.encode({
      version: undefined,
      privateKey: decoded.privateKey,
    });
    let decoded2 = await b58c.decode(encoded);
    if (decoded.privateKey !== decoded2.privateKey) {
      throw new Error(`private keys don't match`);
    }
    if (decoded.privateKey !== decoded2.privateKey) {
      throw new Error(`checksums don't match`);
    }
  }, Promise.resolve());
}

async function toPubKeyHash() {
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

  let parts = await b58c.verify(addr);
  console.info(`\t` + JSON.stringify(parts));

  let check = await b58c.checksum({
    pubKeyHash: parts.pubKeyHash,
  });
  if (parts.check !== check) {
    throw new Error("checksum({ privateKey }) failed");
  }

  try {
    await b58c.checksum({
      privateKey: parts.pubKeyHash,
    });
    throw new Error("allowed checksum of pubKeyHash for privateKey");
  } catch (e) {
    // ignore, expected
  }

  let full = await b58c.encode(parts);
  console.info(`\t${full}`);

  if (full !== addr) {
    throw new Error(`expected '${addr}' but got '${full}'`);
  }
}

async function main() {
  console.info("");
  console.info("To WIF...");
  await toWif();
  console.info(`PASS`);

  console.info("");
  console.info(`To PubKeyHash...`);
  await toPubKeyHash();
  console.info(`PASS`);

  console.info("");
}

main();
