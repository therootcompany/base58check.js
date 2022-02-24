# @root/base58check

Base58Check & WIF for Public Key Hash addresses and Private Keys

## Usage

```bash
npm install --save @root/base58check
```

```js
let Base58Check = require("base58check").Base58Check;

let b58c = Base58Check.create();

// Public Key Hash
let pkh = `XfMBLVNyzPxEELVUUsg7AJAHWKiV9do7Pj`;
let parts = await b58c.verify(pkh);
/*
    {
      "version": "4c",
      "pubKeyHash": "3320974335dc4888b501e965fe5ff3c4421c09c4",
      "check": "9e5443ee"
    }
 */

// Private Key
let wif = "XE7KZ98bqtbomihJqkuRzi6DusLAXegQFBmnATDAUVSCxtcbigHb";
let parts = await b58c.verify(wif);
/*
    {
      "version": "cc",
      "privateKey": "543519e8a781d6986377df6ec18c76fceb270697f16f204408af72edc4fe70de",
      "compressed": true,
      "check": "24aeb2e6"
    }
 */
```

### Options

You can enforce your instance of Base58Check to verify and generate a particular
_version_ of coin, or to use a different Base58 dictionary.

```js
Base58Check.create({
  pubKeyHashVersion: `4c`, // Dash (`00` for Bitcoin)
  privateKeyVersion: `cc`, // Dash (`80` for Bitcoin)
  dictionary: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`,
});
```

## Base58Check Summary

- 1 byte **Version**
- 16 bytes "Compressed" **Public Key Hash**
- 4 bytes **Checksum**

```txt
XxJ7EZT2VyJ821LeAzoT9aDDSuempCikd3

4c ed060e9316ea54396038b7ef703c0616025ddc55 03368b2e

{
  version: '4c',
  pubKeyHash: 'ed060e9316ea54396038b7ef703c0616025ddc55',
  check: '03368b2e'
}
```

## WIF (Wallet Import Format)

- 1 byte **Version**
- 32 bytes **Private Key**
- 1 byte (Optional) **Has Compressed Public Key**
- 4 bytes **Checksum**

```txt
XJxvA5cC4zi3DYeMVUgHunF3nt5UajjXAvJaHnZRMunPNjyKmGfB

cc e51245e19bfc59800445c91d6623a8225f5e521d339fca2a5bbe71fb973dac0f (01) 90d16dc2

{
  version: 'cc',
  privateKey: 'e51245e19bfc59800445c91d6623a8225f5e521d339fca2a5bbe71fb973dac0f',
  compressed: true,
  check: '90d16dc2'
}
```
