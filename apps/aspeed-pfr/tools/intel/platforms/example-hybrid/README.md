# Hybrid ECDSA P-384 + ML-DSA-87 BIOS image example

Same flow as [example-a](../example-a/generate_bios_pfr_image.md), signed with the
[hybrid signature block](../../hybrid_p384_mldsa87_signature_block.md) for AST1080.

Copy into one directory:

- These files
- `pfr_image.py` and the `hybrid_*.pem` test keys from OpenBMC
  `meta-aspeed-sdk/meta-aspeed-pfr/recipes-intel/pfr/files/`
- `intel-pfr-signing-utility` from an OpenBMC build with `PFR_SIGN_SCHEME = "p384-mldsa87"`

Then run:

```bash
./create_bios_pfr_image.sh bios_active.bin
```

| Output | Use |
|---|---|
| `plta-bios_cap.bin.signed` | BIOS update capsule, copy to BMC `/dev/mtd9` |
| `image-bios-pfr` | 128 MB PCH flash image |

The layout matches the default AST1080 provisioning:

| Region | Offset | Size |
|---|---|---|
| BIOS active (dynamic) | 0x0000000 | 0x3000000 |
| BIOS active (static, SHA-384) | 0x3000000 | 0xFE0000 |
| PFM | 0x3FE0000 | 0x20000 |
| Staging | 0x4000000 | 0x2000000 |
| Recovery | 0x6000000 | 0x2000000 |

`pch_test_image_hybrid.tgz` contains both outputs, built from a dummy BIOS
image with the OpenBMC `hybrid_*.pem` keys.

**Note: The `hybrid_*.pem` keys are for test only.**
