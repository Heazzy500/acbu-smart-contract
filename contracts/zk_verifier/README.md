# `zk_verifier` — proof artifact toolchain

The proof artifacts (UltraHonk proof + verification key + public inputs)
accepted by this contract and the `sdk`'s on-chain verifier flow must be
built with **one pinned toolchain**:

| Tool                        | Pinned version    |
|-----------------------------|-------------------|
| Noir (`nargo`)              | `1.0.0-beta.9`    |
| Barretenberg (`bb`)         | `v0.87.0`         |
| `@aztec/bb.js` (JS binding) | `0.87.0`          |
| `@noir-lang/*` packages     | `1.0.0-beta.9`    |

This matches the toolchain of `ultrahonk-soroban-verifier` (see its
`tests/build_circuits.sh`) and the `ultrahonk_rust_verifier` crate the
proof format is designed around.

## Why the pin matters (AZ-011)

UltraHonk proof/VK serialization and constraint semantics changed between
Noir `beta.9` and later betas (e.g. `beta.22`). Artifacts generated with a
different Noir/Barretenberg version than the one the verifier expects will
**not verify on-chain**, even though the circuit source is identical. Never
build the circuits with a different toolchain version; upgrade only by
changing the pin everywhere at once.

```bash
# Install the pinned toolchain
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup -v 1.0.0-beta.9

curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/cpp/installation/install | bash
bbup -v v0.87.0
```
