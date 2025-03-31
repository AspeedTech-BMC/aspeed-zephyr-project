import struct
import hashlib
import argparse
from cryptography.hazmat.primitives import serialization

# Define structure
PFR_DEVID_CERT_INFO_FORMAT = "<II4096s32s97sB"
MAGIC_NUMBER = 0x43455254  # 'CERT' in ASCII
CERT_TYPE = 0

RED = "\033[91m"
RESET = "\033[0m"


def format_hex_dump(data):
    return '\n'.join([' '.join(f'{byte:02x}' for byte in data[i:i+16]) for i in range(0, len(data), 16)])


# Compute SHA-256 hash
def calculate_hash(data):
    return hashlib.sha256(data).digest()


def verify_pfr_cert(binary_file):
    with open(binary_file, "rb") as f:
        # only read size of PFR_DEVID_CERT_INFO_FORMAT
        cert_data = f.read(struct.calcsize(PFR_DEVID_CERT_INFO_FORMAT))

    unpacked_data = struct.unpack(PFR_DEVID_CERT_INFO_FORMAT, cert_data)
    magic_number, data_length, data, hash_value, pubkey, cert_type = unpacked_data

    if magic_number != MAGIC_NUMBER:
        print(f"{RED}Error: Invalid magic number{RESET}")
        return

    if cert_type != CERT_TYPE:
        print(f"{RED}Error: Invalid certificate type{RESET}")
        return

    expected_hash = calculate_hash(data[:data_length])
    if hash_value != expected_hash:
        print(f"{RED}Error: Hash mismatch{RESET}")
        print(f"\nExpected:\n{format_hex_dump(expected_hash)}")
        print(f"\nActual:\n{format_hex_dump(hash_value)}\n")
        return

    print(f"\n==========  Magic Number:\n{hex(magic_number)}")
    print(f"\n==========  Data Length:\n{hex(data_length)}")
    print(f"\n==========  Hash Value:\n{format_hex_dump(hash_value)}")
    print(f"\n==========  Public Key:\n{format_hex_dump(pubkey)}")
    print(f"\n==========  Certificate Type:\n{cert_type}\n\n")
    print("Certchain file verified successfully\n")


# Execute function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate or verify PFR_DEVID_CERT_INFO binary")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser("verify", help="Verify hash")
    verify_parser.add_argument("binary_file", help="Path to the binary file to verify")

    args = parser.parse_args()

    if args.command == "verify":
        verify_pfr_cert(args.binary_file)
    else:
        print(f"{RED}Error: Unknown command{RESET}")
        parser.print_help()
        exit(1)
