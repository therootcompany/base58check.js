# @root/base58check

Base58Check & WIF for Public Key Hash addresses and Private Keys

## Usage

Can convert Public Key Hashes and Private Keys between Hex, Base58Check, and
WIF.

### CLI

```bash
npm install -g @root/base58check
```

```bash
# base58check <key> [version]

base58check XfMBLVNyzPxEELVUUsg7AJAHWKiV9do7Pj
# {
#   "version": "4c",
#   "pubKeyHash": "3320974335dc4888b501e965fe5ff3c4421c09c4"
# }

base58check 3320974335dc4888b501e965fe5ff3c4421c09c4 4c
# XfMBLVNyzPxEELVUUsg7AJAHWKiV9do7Pj
```

### Node.js

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

// Extended Public Key
let xpub = `xpub6EtdcAi4VMbZRDgSaA1WmrqB8asuswgz1toia3YULccxyJXYqdxwqFgeEexVxr8ytJPHZYTrhbYJjqaFumih45awabyaHwUmCvXbGf7sujG`;
let parts = await b58c.decode(xpub); // TODO checksum not checked
/*
    {
      "version": "0488b21e",
      "pubKeyHash": "04832a89a60000000091dbdc89637be3d19851998ba2fac7f85b03b28a65de5c284899e7608f25ee4f0238eddc6cf0b2e8a1bae318affe3661cc071d13c9ad95e77a331a91b58a1b3a7f",
      "check": "c1edc9ce"
    }
 */

// Extended Public Key
let xprv = `xprvA1WUDWFxdE5UGW1XNTnkZnd3K6bdidZBTtzvtEQziBpS3N8tajC4QKyRLmas7DK4HXK76wSXgMV1uV6RbKyM5f4uu1VmguEhAqvzQwr2mrC`;
let parts = await b58c.decode(xprv); // TODO checksum not checked
/*
    {
      "version": "0488ade4",
      "xprv": "04832a89a60000000091dbdc89637be3d19851998ba2fac7f85b03b28a65de5c284899e7608f25ee4f0079842279eca681d40ccc86c6c618f783f4d4339c2431e4ed29e57c7b73be0c69",
      "check": "e986668d"
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
