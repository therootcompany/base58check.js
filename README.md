# @root/base58check

Base58Check & WIF for PubKeyHash and PrivateKeys

## Base58Check

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
