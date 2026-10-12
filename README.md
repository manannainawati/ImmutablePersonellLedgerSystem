# IPLS — Immutable Personnel Ledger System
### Enterprise Distributed Ledger with World State DB, Merkle Trees, and Zero-Knowledge Proofs

IPLS is a production-grade permissioned distributed ledger designed for high-assurance enterprise workforce and facility attendance tracking. Built on the **Hyperledger Fabric architecture**, it guarantees zero-trust tamper resistance, mathematical proof of authority, privacy-preserving compliance verification, and decentralized self-healing consensus.

---

## 🏛️ All 7 Enterprise Security Layers

| Layer | Technology | Security & Governance Guarantee |
|---|---|---|
| **L1: Integrity** | **BLAKE3 Domain-Keyed Hash Chaining** | Fixed `IPLS-attendance-block-hash-v1` domain separation prevents cross-protocol pre-image attacks. Chained headers make historical blocks mathematically immutable. |
| **L2: Consensus** | **Proof of Authority (PoA) + Nakamoto Resolution** | Blocks are only accepted if signed by a registered Higher Official. Split-brain or corrupted forks are automatically healed via Nakamoto longest-valid-chain resolution (`/nodes/resolve`). |
| **L3: Authenticity** | **Ed448 Digital Signatures (RFC 8032)** | Goldilocks curve $\mathbb{F}_{2^{448}-2^{224}-1}$ provides 224-bit security (comparable to AES-256). Complete Edwards curve addition laws ensure immunity to side-channel timing attacks. |
| **L4: Privacy** | **Fernet AES-128-CBC Payload Encryption** | Employee names, shift times, and biometric/badge events are encrypted at rest with facility keys. Ciphertext is stored on-chain; unauthorized observers see zero plaintext. |
| **L5: State Engine** | **World State DB & State Root Commitments** | Implements the Hyperledger Fabric state model: separates append-only ledger history from the current materialized asset state. Every block commits to a **BLAKE3 State Root Hash**. |
| **L6: Auditability** | **BLAKE3 Binary Merkle Trees (SPV Proofs)** | Transactions in every block are structured into a binary Merkle tree. External auditors verify inclusion in $O(\log N)$ time with sibling hashes without downloading the full ledger. |
| **L7: Zero-Knowledge** | **ZKP Range Proofs (Pedersen + CDS94)** | Employees prove shift compliance ($\ge 8.0$ hours) to external regulators using **Pedersen Commitments** ($C = g^v h^r \pmod p$) and **CDS94 1-out-of-2 Disjunctive Proofs** without revealing exact arrival times or timestamps. |

---

## 📂 Reorganized Repository Architecture

```text
BlockchainProjectCode/
├── block.py                  # Block data structure, serialization & hashing
├── blockchain.py             # Blockchain core, mempool batching & consensus
├── world_state.py            # World State DB, personnel roster & State Root
├── contract.py               # Enterprise Chaincode (CRL, Onboarding, Multi-Sig)
├── crypto_utils.py           # Ed448 signing, Fernet encryption & key management
├── hash_utils.py             # Domain-keyed BLAKE3 cryptographic primitives
├── merkle_tree.py            # Binary Merkle tree & SPV audit inclusion proofs
├── zkp_utils.py              # Zero-Knowledge Proofs & Pedersen commitments
├── node.py                   # P2P Node daemon & REST API routes
├── run_network.py            # Single-command 3-node cluster orchestrator
├── setup_network.py          # Key generation & network configuration bootstrap
├── official_client.py        # Standalone official client-side Ed448 signer
├── verify_certificate.py     # Standalone offline SOC-2 audit certificate verifier
├── benchmark_network.py      # Concurrency stress tester & TPS throughput suite
├── network_config.json       # P2P peer registry & official public keys
├── requirements.txt          # Python dependencies (blake3, cryptography, flask, requests)
├── README.md                 # Complete system documentation
├── ROADMAP.md                # Master development roadmap & milestone checklist
├── demo_cheatsheet.md        # Examiner viva guide, walkthrough & model answers
├── .gitignore                # Git ignore configuration
│
├── templates/
│   └── index.html            # Elite cyber-themed web explorer & live dashboard
│
├── tests/                    # Automated Modular Test Suite (30/30 tests pass)
│   ├── __init__.py
│   ├── test_crypto.py        # Ed448, BLAKE3 domain hashing, Fernet AES
│   ├── test_merkle.py        # Binary Merkle tree & SPV inclusion proofs
│   ├── test_chaincode.py     # Double check-in, shift hours, CRL, 2-of-N multi-sig
│   ├── test_blockchain.py    # Genesis, multi-tx mempool, WAL persistence & crash replay
│   ├── test_elite_features.py# Digital badges, SOC-2 audit certificates, mempool throughput
│   └── test_zkp.py           # Pedersen commitments, CDS94 range proofs & ZKP API routes
│
├── demos/                    # Dedicated Standalone Defense & Viva Demonstrations
│   ├── demo_crypto_tamper.py         # Standalone cryptographic & tamper-resistance demo
│   ├── demo_governance.py            # Onboarding, CRL revocation & 2-of-N multi-sig demo
│   ├── demo_tamper_heal.py           # Live multi-node tamper attack & self-healing demo
│   └── demo_network_walkthrough.py   # Interactive P2P cluster walkthrough demo
│
├── keys/                     # Ed448 private keys & facility encryption keys
└── data/                     # Write-Ahead Log persistence (data/node_<port>/chain.jsonl)
```

---

## ⚡ Quickstart

### 1. Install Dependencies & Initialize Keys
```bash
pip install -r requirements.txt
python setup_network.py
```

### 2. Launch 3-Node P2P Network in 1 Command
```bash
python run_network.py
```
* Automatically spawns **Node 5000** (Leader / Explorer), **Node 5001** (Validator), and **Node 5002** (Validator).
* Colors logs per node and automatically opens the interactive dashboard at **`http://localhost:5000`**.
* Press `Ctrl+C` in the terminal to gracefully terminate all 3 processes with zero lingering background ports.

---

## 🧪 Automated Test Suite (30 of 30 Tests Pass)

Execute the comprehensive test suite verifying all mathematical and protocol claims:
```bash
python -m unittest discover tests
```
```text
Ran 30 tests in ~7s
OK
```

---

## 🛡️ Standalone Defense Demonstrations

Four dedicated scripts are available in `demos/` for examiners or live presentations:

1. **Cryptographic Tamper Defense (Offline):**
   ```bash
   python demos/demo_crypto_tamper.py
   ```
2. **On-Chain Governance (CRL Revocation & 2-of-N Multi-Sig):**
   ```bash
   python demos/demo_governance.py
   ```
3. **Multi-Node Tamper Attack & Nakamoto Auto-Healing:**
   ```bash
   python demos/demo_tamper_heal.py
   ```
4. **Interactive P2P Network Walkthrough:**
   ```bash
   python demos/demo_network_walkthrough.py
   ```

---

## 📜 Offline Audit Certificate Verification
External labor compliance officers or auditors can verify an employee's historical attendance completely offline:
```bash
python verify_certificate.py --employee EMP1001
```

---

## ⚡ Concurrency & TPS Benchmark
Run multi-threaded concurrent transaction load tests:
```bash
python benchmark_network.py --txs 30 --workers 5
```
