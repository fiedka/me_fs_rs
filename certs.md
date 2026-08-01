# Certificates

## Official

<https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/default.htm?turl=WordDocuments%2Frootcertificatehashes.htm>

> Releases 7.0 through 10.x support the following SHA1 root certificates.

| Common Name                               | SHA1 Fingerprint                                              |
| ----------------------------------------- | ------------------------------------------------------------- |
| VeriSign Class 3 Public Primary CA – G1   | `74 2c 31 92 e6 07 e4 24 eb 45 49 54 2b e1 bb c5 3e 61 74 e2` |
| VeriSign Class 3 Public Primary CA – G1.5 | `a1 db 63 93 91 6f 17 e4 18 55 09 40 04 15 c7 02 40 b0 ae 6b` |
| VeriSign Class 3 Public Primary CA – G2   | `85 37 1c a6 e5 50 14 3d ce 28 03 47 1b de 3a 09 e8 f8 77 0f` |
| VeriSign Class 3 Public Primary CA – G3   | `13 2d 0d 45 53 4b 69 97 cd b2 d5 c3 39 e2 55 76 60 9b 5c c6` |
| VeriSign Class 3 Public Primary CA – G5   | `4e b6 d5 78 49 9b 1c cf 5f 58 1e ad 56 be 3d 9b 67 44 a5 e5` |
| Go Daddy Class 2 CA                       | `27 96 ba e6 3f 18 01 e2 77 26 1b a0 d7 77 70 02 8f 20 ee e4` |
| Comodo AAA CA                             | `d1 eb 23 a4 6d 17 d6 8f d9 25 64 c2 f1 f1 60 17 64 d8 e3 49` |
| Starfield Class 2 CA                      | `ad 7e 1c 28 b0 64 ef 8f 60 03 40 20 14 c3 d0 e3 37 0e b5 8a` |

## ME 8.0 (X230)

`sh certs.sh | xargs -I '{}' head -c35 '{}' | strings | sort`

- Baltimore CyberTrust Root
- Comodo AAA CA
- Cybertrust Global Root
- Entrust.net CA (2048)
- Entrust Root CA
- Go Daddy Class 2 CA
- GTE CyberTrust Global Root
- Starfield Class 2 CA
- VeriSign Class 3 Primary CA-G1
- VeriSign Class 3 Primary CA-G1.5
- VeriSign Class 3 Primary CA-G2
- VeriSign Class 3 Primary CA-G3
- VeriSign Class 3 Primary CA-G5
- VeriSign Universal Root CA
- Verizon Global

## Format

Examples:

```
00000000: 0356 6572 6953 6967 6e20 436c 6173 7320  .VeriSign Class 
00000010: 3320 5072 696d 6172 7920 4341 2d47 3300  3 Primary CA-G3.
00000020: 001e 0113 2d0d 4553 4b69 97cd b2d5 c339  ....-.ESKi.....9
00000030: e255 7660 9b5c c600 0000 0000 0000 0000  .Uv`.\..........
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0070 86ed 31bb 9da5 4448 803c e215  ...p..1...DH.<..
00000060: edf0 4cfc eaef 3760 109b 37af ff0d 683a  ..L...7`..7...h:
00000070: b79b d100 fa5f 0000 0000 0000 0000 0000  ....._..........
00000080: 0000 0000 0000 00                        .......
```

```
00000000: 0343 7962 6572 7472 7573 7420 476c 6f62  .Cybertrust Glob
00000010: 616c 2052 6f6f 7400 0000 0000 0000 0000  al Root.........
00000020: 0016 015f 43e5 b1bf f878 8cac 1cc7 ca4a  ..._C....x.....J
00000030: 9ac6 222b cc34 c600 0000 0000 0000 0000  .."+.4..........
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 00d0 555f 203a 3264 9855 8098 1963  ....U_ :2d.U...c
00000060: 5b29 5ae5 4a12 da38 1f85 ed94 fbeb 2218  [)Z.J..8......".
00000070: 4106 7100 fa5f 0000 0000 0000 0000 0000  A.q.._..........
00000080: 0000 0000 0000 00                        .......
```

```
00000000: 0345 6e74 7275 7374 2052 6f6f 7420 4341  .Entrust Root CA
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 000f 01b3 1eb1 b740 e36c 8402 dadc 37d4  .......@.l....7.
00000030: 4df5 d467 4952 f900 0000 0000 0000 0000  M..gIR..........
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0077 5a70 9f36 f9ba fa7e 3813 8fd7  ...wZp.6...~8...
00000060: 46eb 7ceb 5b6b f321 6345 b1fc 4f45 cb26  F.|.[k.!cE..OE.&
00000070: 1ad5 5500 fa5f 0000 0000 0000 0000 0000  ..U.._..........
00000080: 0000 0000 0000 00                        .......
```

- 34 bytes: name (fixed length padded with `0`s)
    - initial marker: `03`
    - last byte: real string length (here: 0x1e = 30, 0x16 = 22, 0x0f=15)
- 20 bytes: SHA1 fingerprint
- 28 bytes: `0`s (padding?)
- 32 bytes: ?
- 1   byte: `0` (padding?)
- 2  bytes: `fa5f` (seems to be fixed)
- 17 bytes: `0`s (padding?)
