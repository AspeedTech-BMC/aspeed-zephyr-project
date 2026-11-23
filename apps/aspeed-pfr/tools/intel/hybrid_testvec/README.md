# Hybrid Intel PFR test vectors

All keys and seeds in this directory are test-only and must never be provisioned on a production platform.

Run from this directory with Python 3 and `cryptography` 50.

```sh
python3 gen_hybrid_testvec.py
python3 gen_hybrid_testvec.py --verify kc_cert.bin
python3 gen_hybrid_testvec.py --verify pfm.bin
python3 gen_hybrid_testvec.py --verify /path/to/image.bin --root-hash root_key_hash.bin
```

Generation writes beside the script. The verifier defaults to the local
`root_key_hash.bin` and accepts an explicit trusted hash as 48 raw bytes or
96 hex digits. It exits 1 on failure.

| File | Contents |
| --- | --- |
| `{root,csk}_ec_private.pem` | Unencrypted PKCS#8 P-384 test key |
| `{root,csk}_ec_public.bin` | 96 bytes, big-endian X followed by Y |
| `{root,csk}_mldsa_seed.bin` | 32-byte ML-DSA-87 private-key seed |
| `{root,csk}_mldsa_public.bin` | 2592-byte FIPS 204 public key |
| `root_key_hash.bin` | 48-byte SHA-384 of the root EC and ML-DSA public bytes in that order |
| `kc_cert.bin` | Root-signed BMC PFM cancellation certificate for CSK ID 1 |
| `pfm.bin` | BMC PFM signed by CSK ID 2, with the root-signed CSK entry |

## Spec ambiguities and fixture choices

- The spec leaves the Intel cancellation type values and payload layout to
  firmware. The fixture uses `PcType = 0x103` and a little-endian uint32 key
  ID followed by 124 zero bytes. The verifier chooses the layout from bit 8,
  as specified, and treats the entire cancellation payload as opaque.
- The spec defines `PcLength` but leaves the PFM header and body to firmware.
  The fixture uses `PcType = 3`, a 32-byte header and one 16-byte read-only
  SPI region without a region hash. The header's `Length` includes the header
  and region (48 bytes). Zero fill extends the protected content to 128 bytes,
  and both Block0 digests cover that fill. The PFM uses CSK ID 2 so ID 1 is
  available for the cancellation fixture.
- Section 3.3 places the X, Y and ML-DSA public-key field rows under the
  permission table. The field offsets are relative to the start of the key
  entry, as also implied by section 5.
- The verifier checks `Sha256Pc` and reserved and padding bytes as defined
  in section 3, including checks beyond the firmware sequence in section 6.
  It checks one signature block and its declared protected bytes starting at
  file offset zero. Payload structure, nested signatures, platform acceptance
  rules and UFM cancellation state are outside that check. Bytes after the
  declared protected content are allowed.
- Fixed labels derive the keys. The signing APIs use randomized ECDSA and
  hedged ML-DSA, so signature bytes can vary between runs.

## Verification results

The generated cancellation certificate passed all 20 applicable checks.
The generated PFM passed all 28 applicable checks.
