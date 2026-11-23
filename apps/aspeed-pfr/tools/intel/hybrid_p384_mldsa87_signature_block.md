# Intel PFR Hybrid Signature Block: ECDSA P-384 + ML-DSA-87

ASPEED extension to the Intel PFR signature block. Every signed structure
(PFM, update capsule, key cancellation certificate, decommission capsule, AFM,
CPLD capsule) carries an ECDSA P-384 signature **and** an ML-DSA-87 signature
at every level of the chain. Firmware accepts a structure only if **both**
signatures verify at every level.

Firmware: `apps/aspeed-pfr/src/intel_pfr/intel_pfr_sig_hybrid.c`
(scheme name `p384_mldsa87`).

## 1. Constants

| Name | Value | Notes |
|---|---|---|
| `BLOCK0TAG` | `0xB6EAFD19` | Intel, unchanged |
| `BLOCK1TAG` | `0xF27F28D7` | Intel, unchanged |
| `BLOCK1_ROOTENTRY_TAG` | `0xA757A046` | Intel, unchanged |
| `BLOCK1CSKTAG` | `0x14711C2F` | Intel, unchanged |
| `BLOCK1_BLOCK0ENTRYTAG` | `0x15364367` | Intel, unchanged |
| `PUBLIC_P384_MLDSA87_TAG` | `0x49C7FFDC` | new; LE u32 of `SHA-256("ASPEED-PFR PUBLIC P384-MLDSA87")[0:4]` |
| `SIGNATURE_P384_MLDSA87_TAG` | `0x2E30EA3F` | new; LE u32 of `SHA-256("ASPEED-PFR SIGNATURE P384-MLDSA87")[0:4]` |
| Signature block size | `0x4000` (16384) | protected content starts here |

All multi-byte integer fields (tags, lengths, permissions, key IDs) are
little-endian `uint32`.

## 2. Encodings

| Item | Size | Encoding |
|---|---|---|
| ECDSA P-384 public key X, Y | 48 + 48 | big-endian, zero-padded to 48 bytes |
| ECDSA P-384 signature R, S | 48 + 48 | big-endian, zero-padded to 48 bytes |
| ML-DSA-87 public key | 2592 | FIPS 204 `pkEncode` |
| ML-DSA-87 signature | 4628 | FIPS 204 `sigEncode` (4627 bytes) followed by one `0x00` byte |

ML-DSA-87 is FIPS 204 **pure** ML-DSA with an **empty context string**
(no pre-hash). Hedged or deterministic signing are both accepted.
This is what Caliptra `MLDSA87_SIGNATURE_VERIFY` (reached through
`MC_MLDSA87_SIG_VERIFY`) implements; it rejects a signature whose last byte
is not zero. The signed message must not exceed 4096 bytes; the largest
message in this format is 2700 bytes.

## 3. Signature block layout

Offsets are from the start of the signature block. Unused bytes are zero.

```
0x0000  Block0                 128
0x0080  Block1 header           16
0x0090  Root entry            2704
0x0B20  CSK entry             7432   (absent in key cancellation certificates)
0x2828  Block0 entry          4732   (at 0x0B20 when there is no CSK entry)
0x3AA4  zero padding          1372   (from 0x1D9C when there is no CSK entry)
0x4000  protected content
```

### 3.1 Block0 (128 bytes, Intel format)

| Off | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | Tag | `BLOCK0TAG` |
| 4 | 4 | PcLength | protected content length, multiple of 128, ≥ 128 |
| 8 | 4 | PcType | Intel PC type |
| 12 | 4 | Reserved | 0 |
| 16 | 32 | Sha256Pc | SHA-256 of protected content (not checked by firmware) |
| 48 | 48 | Sha384Pc | SHA-384 of protected content (checked) |
| 96 | 32 | Reserved | must be 0 |

Protected content is the `PcLength` bytes starting at offset `0x4000`.
Key cancellation certificates and decommission capsules must have
`PcLength = 128`.

A structure has no CSK entry exactly when `PcType & 0x100` is set
(key cancellation certificate).

### 3.2 Block1 header (16 bytes)

| Off | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | Tag | `BLOCK1TAG` |
| 4 | 12 | Reserved | 0 |

### 3.3 Key entry (2704 bytes) — used for the root entry and the CSK entry

| Off | Size | Field | Root entry | CSK entry |
|---|---|---|---|---|
| 0 | 4 | Tag | `BLOCK1_ROOTENTRY_TAG` | `BLOCK1CSKTAG` |
| 4 | 4 | PubKeyMagic | `PUBLIC_P384_MLDSA87_TAG` | `PUBLIC_P384_MLDSA87_TAG` |
| 8 | 4 | KeyPermission | `0xFFFFFFFF` | Intel permission bits |
| 12 | 4 | KeyId | `0xFFFFFFFF` | 0–127 (Intel CSK ID) |
| 16 | 48 | EcPubX | | |
| 64 | 48 | EcPubY | | |
| 112 | 2592 | MldsaPub | | |

The CSK `KeyPermission` must have the bit for the structure's `PcType`:

| PcType | Structure | Permission bit |
|---|---|---|
| 0 | ROT update capsule | `0x10` |
| 1 | PCH PFM | `0x01` |
| 2 | PCH update capsule | `0x02` |
| 3 | BMC PFM | `0x04` |
| 4 | BMC update capsule | `0x08` |
| 5 | PCH seamless update capsule | `0x02` |
| 6, 8 | AFM, AFM per device | `0x20` |
| 7 | Intel CPLD update capsule | `0x40` |
| `0x200` | Decommission capsule | `0x10` |

### 3.4 CSK entry (7432 bytes)

| Off | Size | Field |
|---|---|---|
| 0 | 2704 | Key entry (3.3) |
| 2704 | 4 | SignatureMagic = `SIGNATURE_P384_MLDSA87_TAG` |
| 2708 | 48 | EcSigR |
| 2756 | 48 | EcSigS |
| 2804 | 4628 | MldsaSig |

### 3.5 Block0 entry (4732 bytes)

| Off | Size | Field |
|---|---|---|
| 0 | 4 | Tag = `BLOCK1_BLOCK0ENTRYTAG` |
| 4 | 4 | SignatureMagic = `SIGNATURE_P384_MLDSA87_TAG` |
| 8 | 48 | EcSigR |
| 56 | 48 | EcSigS |
| 104 | 4628 | MldsaSig |

## 4. Signing

### 4.1 CSK entry

Message `M_csk` = CSK entry bytes `[4, 2704)` (PubKeyMagic through MldsaPub,
2700 bytes).

- `EcSigR, EcSigS` = ECDSA-P384(root EC private key, SHA-384(`M_csk`))
- `MldsaSig` = ML-DSA-87.Sign(root ML-DSA private key, `M_csk`, ctx = "") ‖ `0x00`

### 4.2 Block0 entry

Message `M_b0` = the 128-byte Block0.
Signing key: the CSK keys, or the root keys when there is no CSK entry.

- `EcSigR, EcSigS` = ECDSA-P384(EC private key, SHA-384(`M_b0`))
- `MldsaSig` = ML-DSA-87.Sign(ML-DSA private key, `M_b0`, ctx = "") ‖ `0x00`

Block0 must be final (Sha256Pc / Sha384Pc filled in) before it is signed.

### 4.3 Nested structures

Capsules nest exactly as in Intel PFR, with every signature block being
`0x4000` bytes:

```
update capsule = SigBlk(capsule) ‖ SigBlk(PFM) ‖ PFM body ‖ compressed payload
```

The outer `PcLength` covers the inner signature block. Sign inner structures
first. All signature blocks on a platform chain to the same root keys.

## 5. Root key provisioning

UFM `ROOT_KEY_HASH` (48 bytes) =
SHA-384(Root.EcPubX ‖ Root.EcPubY ‖ Root.MldsaPub), i.e. the 2688 bytes at
root entry offsets `[16, 2704)` exactly as stored.

Because the provisioned hash covers both keys, an ECDSA-only or LMS image
cannot match it, so a hybrid platform cannot be downgraded to a single
algorithm.

## 6. Firmware checks (in order)

1. Root entry `PubKeyMagic` selects this scheme.
2. Key cancellation: CSK `KeyId` (CSK entry offset 12) not cancelled for this PC type.
3. Block1 Tag; root entry Tag, `KeyPermission = KeyId = 0xFFFFFFFF`;
   SHA-384 of root keys equals UFM `ROOT_KEY_HASH`.
4. CSK entry (if present): Tag, `PubKeyMagic`, permission bit for `PcType`,
   `SignatureMagic`, then both CSK signatures with the root keys.
5. Block0 entry: Tag, `SignatureMagic`, then both Block0 signatures with the
   CSK keys (or root keys).
6. Block0: Tag, `PcLength` rules, Reserved2 = 0, Sha384Pc matches the
   protected content.

Any failure rejects the structure.

## 7. Scope on AST1080

- Intel PFR ROT update capsules (`PFR_CPLD_UPDATE_CAPSULE`) are rejected
  (`CONFIG_PFR_ROT_UPDATE_CAPSULE=n`); AST1080 firmware is updated by PLDM.
- Decommission capsules and key cancellation certificates use this format.

## 8. Test vectors

`hybrid_testvec/` holds fixed root/CSK test key pairs, their `ROOT_KEY_HASH`,
a signed key cancellation certificate and PFM, and a spec-only verifier
(`gen_hybrid_testvec.py --verify`).

A signing tool is conformant when, given the same keys and inputs:

1. its output equals the reference byte-for-byte except `EcSigR`, `EcSigS`
   and `MldsaSig` (ECDSA and hedged ML-DSA are randomized), and
2. every signature in its output verifies with the reference public keys.
