#!/usr/bin/env python3
import argparse
from hashlib import sha256, sha384
from pathlib import Path
from struct import pack, unpack_from

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, utils

HERE = Path(__file__).resolve().parent
BLOCK_SIZE = 0x4000
BLOCK0_TAG = 0xB6EAFD19
BLOCK1_TAG = 0xF27F28D7
ROOT_TAG = 0xA757A046
CSK_TAG = 0x14711C2F
BLOCK0_ENTRY_TAG = 0x15364367
PUBLIC_MAGIC = 0x49C7FFDC
SIGNATURE_MAGIC = 0x2E30EA3F
CANCEL = 0x100
DECOMMISSION = 0x200
PERMISSIONS = {0: 0x10, 1: 0x01, 2: 0x02, 3: 0x04, 4: 0x08, 5: 0x02,
               6: 0x20, 7: 0x40, 8: 0x20, DECOMMISSION: 0x10}


def u32(*values):
    return pack("<" + "I" * len(values), *values)


def be48(value):
    return value.to_bytes(48, "big")


def save_keys(name):
    label = b"ASPEED Intel-PFR hybrid test vector v1/" + name.encode("ascii")
    curve = ec.SECP384R1()
    scalar = int.from_bytes(sha384(label + b"/P-384").digest(), "big")
    ec_key = ec.derive_private_key(1 + scalar % (curve.group_order - 1), curve)
    seed = sha256(label + b"/ML-DSA-87").digest()
    pq_key = mldsa.MLDSA87PrivateKey.from_seed_bytes(seed)
    nums = ec_key.public_key().public_numbers()
    ec_pub = be48(nums.x) + be48(nums.y)
    pq_pub = pq_key.public_key().public_bytes_raw()

    (HERE / f"{name}_ec_private.pem").write_bytes(ec_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (HERE / f"{name}_ec_public.bin").write_bytes(ec_pub)
    (HERE / f"{name}_mldsa_seed.bin").write_bytes(seed)
    (HERE / f"{name}_mldsa_public.bin").write_bytes(pq_pub)
    return (ec_key, pq_key), ec_pub + pq_pub


def sign(message, keys):
    ec_key, pq_key = keys
    der = ec_key.sign(message, ec.ECDSA(hashes.SHA384()))
    r, s = utils.decode_dss_signature(der)
    return u32(SIGNATURE_MAGIC) + be48(r) + be48(s) + pq_key.sign(message, b"") + b"\0"


def signed_image(body, pc_type, root, csk_entry=b"", signer=None):
    root_keys, root_public = root
    block0 = (u32(BLOCK0_TAG, len(body), pc_type, 0) + sha256(body).digest()
              + sha384(body).digest() + bytes(32))
    root_entry = u32(ROOT_TAG, PUBLIC_MAGIC, 0xFFFFFFFF, 0xFFFFFFFF) + root_public
    block = (block0 + u32(BLOCK1_TAG) + bytes(12) + root_entry + csk_entry
             + u32(BLOCK0_ENTRY_TAG) + sign(block0, signer or root_keys))
    return block + bytes(BLOCK_SIZE - len(block)) + body


def generate():
    root = save_keys("root")
    csk_keys, csk_public = save_keys("csk")
    (HERE / "root_key_hash.bin").write_bytes(sha384(root[1]).digest())

    # intel_pfr_verification.h: PFR_BMC_PFM=3, BMC_PFM_CANCELLATION=0x103.
    # intel_pfr_key_cancellation.c: key ID at offset 0, reserved data at offset 4.
    # intel_pfr_key_cancellation.h: KCH_CAN_CERT_RESERVED_SIZE=124.
    (HERE / "kc_cert.bin").write_bytes(signed_image(u32(1) + bytes(124), 0x103, root))

    # intel_pfr_definitions.h: PFMTAG=0x02B3CE1D, SIGN_BMC_PFM_BIT2=0x04.
    # intel_pfr_pfm_manifest.h: PFM_STRUCTURE (32 bytes), SPI_REGION=1, PFM_SPI_DEFINITION (16 bytes).
    region = pack("<BBHIII", 1, 1, 0, 0, 0, 0x1000)
    header = pack("<IBBHI16sI", 0x02B3CE1D, 1, 0, 1, 0, bytes(16), 32 + len(region))
    body = (header + region).ljust(128, b"\0")
    csk = u32(CSK_TAG, PUBLIC_MAGIC, PERMISSIONS[3], 2) + csk_public
    csk_entry = csk + sign(csk[4:], root[0])
    (HERE / "pfm.bin").write_bytes(signed_image(body, 3, root, csk_entry, csk_keys))


def verify_ec(public, signature, message):
    x = int.from_bytes(public[:48], "big")
    y = int.from_bytes(public[48:96], "big")
    key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP384R1()).public_key()
    r = int.from_bytes(signature[:48], "big")
    s = int.from_bytes(signature[48:96], "big")
    key.verify(utils.encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA384()))


def verify_mldsa(public, signature, message):
    key = mldsa.MLDSA87PublicKey.from_public_bytes(public[96:])
    key.verify(signature, message, b"")


def verify(data, root_hash):
    passed = True

    def check(name, ok):
        nonlocal passed
        print(f"{'PASS' if ok else 'FAIL'} {name}")
        passed = passed and ok

    def signatures(name, public, entry, message):
        check(f"{name} signature magic", unpack_from("<I", entry)[0] == SIGNATURE_MAGIC)
        check(f"{name} ML-DSA padding byte", entry[4727:] == b"\0")
        for algorithm, verifier, sig in (
            ("ECDSA P-384", verify_ec, entry[4:100]),
            ("ML-DSA-87", verify_mldsa, entry[100:4727]),
        ):
            try:
                verifier(public, sig, message)
            except (InvalidSignature, ValueError):
                check(f"{name} {algorithm} signature", False)
            else:
                check(f"{name} {algorithm} signature", True)

    check("Signature block present", len(data) >= BLOCK_SIZE)
    if not passed:
        return False

    block0 = data[:0x80]
    tag, length, pc_type = unpack_from("<III", block0)
    cancellation = bool(pc_type & CANCEL)
    body = data[BLOCK_SIZE:BLOCK_SIZE + length]
    check("Block0 tag", tag == BLOCK0_TAG)
    check("Block0 PcLength", length >= 128 and length % 128 == 0
          and (not (cancellation or pc_type == DECOMMISSION) or length == 128))
    check("Protected content present", len(body) == length)
    check("Block0 reserved bytes", not any(block0[12:16] + block0[96:128]))
    check("Block0 Sha256Pc", len(body) == length and block0[16:48] == sha256(body).digest())
    check("Block0 Sha384Pc", len(body) == length and block0[48:96] == sha384(body).digest())

    check("Block1 tag", unpack_from("<I", data, 0x80)[0] == BLOCK1_TAG)
    check("Block1 reserved bytes", not any(data[0x84:0x90]))
    tag, magic, permission, key_id = unpack_from("<IIII", data, 0x90)
    check("Root tag", tag == ROOT_TAG)
    check("Root public key magic", magic == PUBLIC_MAGIC)
    check("Root permission", permission == 0xFFFFFFFF)
    check("Root key ID", key_id == 0xFFFFFFFF)
    root = data[0xA0:0xB20]
    check("ROOT_KEY_HASH", sha384(root).digest() == root_hash)

    if cancellation:
        block0_offset, padding_offset, signer = 0xB20, 0x1D9C, root
    else:
        tag, magic, permission, key_id = unpack_from("<IIII", data, 0xB20)
        check("CSK tag", tag == CSK_TAG)
        check("CSK public key magic", magic == PUBLIC_MAGIC)
        check("CSK key ID range", key_id <= 127)
        check("CSK permission for PcType", bool(permission & PERMISSIONS.get(pc_type, 0)))
        signatures("CSK", root, data[0x15B0:0x2828], data[0xB24:0x15B0])
        block0_offset, padding_offset, signer = 0x2828, 0x3AA4, data[0xB30:0x15B0]

    check("Block0 entry tag", unpack_from("<I", data, block0_offset)[0] == BLOCK0_ENTRY_TAG)
    signatures("Block0", signer, data[block0_offset + 4:padding_offset], block0)
    check("Signature block zero padding", not any(data[padding_offset:BLOCK_SIZE]))
    return passed


def main():
    parser = argparse.ArgumentParser(description="Generate or verify hybrid Intel-PFR test vectors.")
    parser.add_argument("--verify", type=Path, metavar="IMAGE")
    parser.add_argument("--root-hash", type=Path, metavar="FILE",
                        help="trusted raw or hex SHA-384 hash (default: generated root_key_hash.bin)")
    args = parser.parse_args()
    if args.verify is None:
        if args.root_hash is not None:
            parser.error("--root-hash requires --verify")
        generate()
        return 0

    try:
        data = args.verify.read_bytes()
        root_hash = (args.root_hash or HERE / "root_key_hash.bin").read_bytes()
        if len(root_hash) != 48:
            root_hash = bytes.fromhex(root_hash.decode("ascii"))
        if len(root_hash) != 48:
            raise ValueError("trusted root hash must be 48 bytes")
    except (OSError, ValueError) as error:
        parser.exit(1, f"FAIL {error}\n")
    return 0 if verify(data, root_hash) else 1


if __name__ == "__main__":
    raise SystemExit(main())
