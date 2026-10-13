# ⚡ IPLS — Master PowerShell & Backend Command Runbook
**Complete Start-to-Finish Command Reference for Terminal Demonstrations & Viva Defense**

> **💡 Pro-Tip for Faculty Presentation:** You have two ways to run these demonstrations:
> 1. **Automated Interactive Menu:** Run `powershell -ExecutionPolicy Bypass -File .\demo_showcase.ps1` to launch an interactive, color-coded walkthrough menu.
> 2. **Manual Copy-Paste:** Follow the step-by-step PowerShell or `curl.exe` commands below side-by-side with your browser dashboard at `http://localhost:5000`.

---

## 📋 Table of Contents
1. [Phase 0: Environment Setup & Automated Test Suite (36/36 Tests)](#phase-0-environment-setup--automated-test-suite)
2. [Phase 1: Starting the Multi-Node Cluster & Process Inspection](#phase-1-starting-the-multi-node-cluster)
3. [Phase 2: Inspecting the Raw On-Disk Database & JSON Files](#phase-2-inspecting-the-raw-on-disk-database--json-files)
4. [Phase 3: Inspecting the World State Database Inside Nodes](#phase-3-inspecting-the-world-state-database-inside-nodes)
5. [Phase 4: Querying Blockchain Ledgers Across All 3 Nodes](#phase-4-querying-blockchain-ledgers-across-all-3-nodes)
6. [Phase 5: Submitting Signed Transactions from Terminal (CLI & REST)](#phase-5-submitting-signed-transactions-from-terminal-cli)
7. [Phase 6: Advanced Governance (CRL Revocation & 2-of-N Multi-Sig)](#phase-6-advanced-governance-crl-revocation--2-of-n-multi-sig)
8. [Phase 7: Simulating Attacks & Self-Healing in Terminal](#phase-7-simulating-attacks--self-healing-in-terminal)
9. [Phase 8: Zero-Knowledge Privacy Proofs (ZKP) in Terminal](#phase-8-zero-knowledge-privacy-proofs-zkp-in-terminal)
10. [Phase 9: SPV Merkle Proofs & Offline Certificate Verification](#phase-9-spv-merkle-proofs--offline-certificate-verification)
11. [Phase 10: High-Throughput Concurrency & TPS Stress Benchmark](#phase-10-high-throughput-concurrency--tps-stress-benchmark)
12. [Phase 11: Cryptographic Employee Digital Identity Badges](#phase-11-cryptographic-employee-digital-identity-badges)
13. [Phase 12: Standalone Demo Scripts Quick-Runner](#phase-12-standalone-demo-scripts-quick-runner)
14. [Quick Top-5 Presentation Cheat Sheet](#quick-top-5-presentation-cheat-sheet)

---

## Phase 0: Environment Setup & Automated Test Suite

### 1. Install Required Python Dependencies
```powershell
pip install -r requirements.txt
```
*Installs cryptographic dependencies: `blake3` (domain-keyed tree hashing), `cryptography` (RFC 8032 Ed448 engine & Fernet), `flask` (REST node daemon), and `requests`.*

### 2. Generate Genesis Keys & Consortium Configuration
```powershell
python setup_network.py
```
*Generates:*
- `network_config.json`: Master peer topology, consortium policies, official public keys, and facility encryption key.
- `keys/OFFICIAL_A.key` & `keys/OFFICIAL_B.key`: 448-bit Edwards-curve private signing keys.

### 3. Run the Full Automated Test Suite (36/36 Unit & Integration Tests)
```powershell
python -m unittest discover tests
```
* **What to tell your professor:**  
  *"Sir, before starting any server, our automated test suite verifies all mathematical invariants across 36 tests: RFC 8032 Ed448 signature validity, BLAKE3 domain-keyed hash chaining, Merkle tree inclusion proofs, World State determinism, live state tampering detection, replay protection, and 768-bit ZKP range proofs with a 100% pass rate."*

### 4. Run Dedicated Security Audit Regression Tests
```powershell
python -m unittest tests/test_audit_fixes.py
```
*Runs regression tests verifying:*
- **Finding A:** Live in-memory state tampering detection.
- **Finding B:** PoA block-level proposer identity and header signature enforcement.
- **Finding C:** Transaction metadata contradiction rejection.
- **Finding D:** Monotonic timestamp replay attack prevention.
- **Finding E:** Non-finite timestamp (NaN, Inf) strict sanitization.
- **Certificate Verifier:** Rejection of fraudulent claims, bogus signatures, and fake Merkle proofs.

---

## Phase 1: Starting the Multi-Node Cluster

### Option A: Launch All 3 Nodes Concurrently (Recommended)
```powershell
python run_network.py
```
*Automatically spawns Node 5000 (Consortium Leader / Explorer), Node 5001 (Validator), and Node 5002 (Validator) with color-coded log multiplexing and opens your browser to `http://localhost:5000`.*

### Option B: Launch in 3 Separate PowerShell Windows (Manual Mode)
If your professor wants to see each node running independently in separate terminal windows:
* **Terminal 1 (Node 5000 - Port 5000):**
  ```powershell
  python node.py --port 5000
  ```
* **Terminal 2 (Node 5001 - Port 5001):**
  ```powershell
  python node.py --port 5001
  ```
* **Terminal 3 (Node 5002 - Port 5002):**
  ```powershell
  python node.py --port 5002
  ```

### Option C: Clean Reset Network to Genesis (Wipe On-Disk Storage)
```powershell
python run_network.py --clean
```
*Wipes all on-disk WAL files in `data/` and starts a brand new, clean consortium ledger from Genesis Block #0.*

### Verify Node Processes & Listening Ports
```powershell
Get-NetTCPConnection -LocalPort 5000, 5001, 5002 | Select-Object LocalPort, State, OwningProcess | Format-Table
```

### Check Live Peer Cluster Connectivity & Latencies
* **PowerShell:**
  ```powershell
  Invoke-RestMethod http://localhost:5000/nodes/peers_status | Select-Object port, online, height, latency_ms, valid | Format-Table -AutoSize
  ```
* **curl.exe:**
  ```cmd
  curl.exe -s http://localhost:5000/nodes/peers_status
  ```

---

## Phase 2: Inspecting the Raw On-Disk Database & JSON Files
*(When the professor asks: "Show me where the database and files actually live on disk")*

### 1. Show the On-Disk Directory Structure
```powershell
Get-ChildItem -Path .\data\ -Recurse | Select-Object FullName, Length | Format-Table
```
*Proves that each node maintains an isolated, independent database directory: `data/node_5000/chain.jsonl`, `data/node_5001/chain.jsonl`, and `data/node_5002/chain.jsonl`.*

### 2. Inspect Number of Committed Blocks on Disk
```powershell
(Get-Content .\data\node_5000\chain.jsonl).Count
```

### 3. View Raw Write-Ahead Log (JSONL) Records Directly
```powershell
Get-Content .\data\node_5000\chain.jsonl -Tail 3
```

### 4. Format the On-Disk Ledger into a Structured Table
```powershell
Get-Content .\data\node_5000\chain.jsonl | ForEach-Object { $_ | ConvertFrom-Json } | Select-Object index, official_id, timestamp, hash, state_root | Format-Table -AutoSize
```
* **What to show:** Point out that every single block has an immutable 256-bit BLAKE3 hash linking back to `previous_hash` and commits directly to the `state_root`.*

### 5. Inspect a Raw Block on Disk in Full Detail
```powershell
Get-Content .\data\node_5000\chain.jsonl -Tail 1 | ConvertFrom-Json | ConvertTo-Json -Depth 4
```
* **What to explain:**  
  1. `encrypted_payload`: Biometric and personal identity fields are encrypted at rest with AES-GCM Fernet keys.
  2. `signature`: 448-bit Ed448 signature over canonical header/transaction bytes guaranteeing non-repudiation.
  3. `state_root`: Snapshot of all entity balances and status after this block executed.
  4. `merkle_root`: Merkle tree root of all transactions within this block.

### 6. Inspect the Consortium Network Configuration
```powershell
Get-Content .\network_config.json | ConvertFrom-Json | Select-Object consensus, hash_algorithm, signature_algorithm, peers | Format-List
```

### 7. Inspect Registered Official Ed448 Public Keys
```powershell
(Get-Content .\network_config.json | ConvertFrom-Json).officials | Format-List
```

---

## Phase 3: Inspecting the World State Database Inside Nodes
*(When the professor asks: "Show me the World State / Current Entity Database")*

### 1. View the Entire World State Database of Node 5000
* **PowerShell:**
  ```powershell
  Invoke-RestMethod http://localhost:5000/state | ConvertTo-Json -Depth 4
  ```
* **curl.exe:**
  ```cmd
  curl.exe -s http://localhost:5000/state
  ```

### 2. View All Personnel and Their Live Presence Status
```powershell
(Invoke-RestMethod http://localhost:5000/state).world_state.employees | Format-Table -AutoSize
```
*Displays Employee IDs, Departments, Status (`IN` or `OUT`), and Total Cumulative Seconds Worked.*

### 3. Query Specific Employee Records (`EMP1001`)
```powershell
(Invoke-RestMethod http://localhost:5000/state).world_state.employees.EMP1001 | Format-List
```
*Sample Output:*
```text
department             : Engineering
status                 : IN
last_check_in          : 1791875828.12
last_check_out         : None
last_action_timestamp  : 1791875828.12
total_seconds_worked   : 3600.0
registered_by          : OFFICIAL_A
```

### 4. Query the On-Chain Certificate Revocation List (CRL)
```powershell
(Invoke-RestMethod http://localhost:5000/state).world_state.officials | Format-Table -AutoSize
```
*Shows active higher officials vs revoked keys (`ACTIVE` or `REVOKED`).*

### 5. Compare the State Root Hash Across All 3 Nodes
```powershell
[PSCustomObject]@{
    Node5000_StateRoot = (Invoke-RestMethod http://localhost:5000/state).state_root
    Node5001_StateRoot = (Invoke-RestMethod http://localhost:5001/state).state_root
    Node5002_StateRoot = (Invoke-RestMethod http://localhost:5002/state).state_root
    Live_State_Integrity = (Invoke-RestMethod http://localhost:5000/state).live_state_valid
} | Format-List
```
* **What to tell your professor:**  
  *"Sir, notice that all 3 nodes have the exact same 256-bit State Root Hash and `live_state_valid = True`. This mathematically proves that all nodes have reached 100% deterministic consensus on the active World State database."*

---

## Phase 4: Querying Blockchain Ledgers Across All 3 Nodes

### 1. Compare Ledger Heights of All 3 Nodes in 1 Object
```powershell
[PSCustomObject]@{
    Node5000_Height = (Invoke-RestMethod http://localhost:5000/chain).Length
    Node5001_Height = (Invoke-RestMethod http://localhost:5001/chain).Length
    Node5002_Height = (Invoke-RestMethod http://localhost:5002/chain).Length
    Consensus = "Proof of Authority (PoA) - Ed448"
} | Format-List
```

### 2. View the Full Ledger Table of Node 5000
```powershell
(Invoke-RestMethod http://localhost:5000/chain) | Select-Object index, official_id, timestamp, hash, state_root, valid | Format-Table -AutoSize
```

### 3. View the Genesis Block (#0) JSON
```powershell
(Invoke-RestMethod http://localhost:5000/chain)[0] | ConvertTo-Json -Depth 3
```

### 4. View the Latest Block with Decrypted Payload
```powershell
(Invoke-RestMethod http://localhost:5000/chain)[-1] | Select-Object index, hash, encrypted_payload, decrypted, signature, state_root | Format-List
```

---

## Phase 5: Submitting Signed Transactions from Terminal (CLI & REST)

### 1. Client-Side Sign & Submit a Check-In for EMP1001
```powershell
python official_client.py OFFICIAL_A EMP1001 CHECK_IN --node http://localhost:5000
```
*Signs the transaction locally with `keys/OFFICIAL_A.key` (Ed448) and broadcasts it to Node 5000.*

### 2. Verify Smart Contract Double Check-In Rejection
```powershell
python official_client.py OFFICIAL_A EMP1001 CHECK_IN --node http://localhost:5000
```
*Fails immediately with:*  
`ContractViolation: EMP1001 is already checked in. Cannot double check in.`

### 3. Client-Side Sign & Submit a Check-Out for EMP1001
```powershell
python official_client.py OFFICIAL_A EMP1001 CHECK_OUT --node http://localhost:5000
```
*Computes shift time elapsed, updates `last_action_timestamp`, adds to cumulative hours worked, and sets status to `OUT`.*

### 4. Onboard a New Employee (`EMP2001`) via REST API
* **PowerShell:**
  ```powershell
  Invoke-RestMethod -Method Post http://localhost:5000/portal/sign_and_submit -ContentType "application/json" -Body '{"official_id":"OFFICIAL_A","employee_id":"EMP2001","action":"REGISTER_EMPLOYEE","extra":{"department":"Robotics"}}' | ConvertTo-Json -Depth 3
  ```
* **curl.exe:**
  ```cmd
  curl.exe -X POST http://localhost:5000/portal/sign_and_submit -H "Content-Type: application/json" -d "{\"official_id\":\"OFFICIAL_A\",\"employee_id\":\"EMP2001\",\"action\":\"REGISTER_EMPLOYEE\",\"extra\":{\"department\":\"Robotics\"}}"
  ```

### 5. Check In the Newly Registered Employee
```powershell
python official_client.py OFFICIAL_A EMP2001 CHECK_IN --node http://localhost:5000
```

---

## Phase 6: Advanced Governance (CRL Revocation & 2-of-N Multi-Sig)

### 1. Run the Complete Governance Test Demonstration Script
```powershell
python demos/demo_governance.py
```
*Demonstrates onboarding, CRL key revocation, and 2-of-N multi-sig emergency overrides with 100% compliance.*

### 2. Revoke an Official's Key on the Live Network (On-Chain CRL)
```powershell
Invoke-RestMethod -Method Post http://localhost:5000/portal/sign_and_submit -ContentType "application/json" -Body '{"official_id":"OFFICIAL_A","employee_id":"OFFICIAL_B","action":"REVOKE_OFFICIAL","extra":{"target_official":"OFFICIAL_B"}}' | ConvertTo-Json -Depth 3
```

### 3. Verify that the Revoked Key is Permanently Blocked
```powershell
python official_client.py OFFICIAL_B EMP1001 CHECK_IN --node http://localhost:5000
```
*Rejection confirmed: Node rejects blocks signed by revoked official with `Official 'OFFICIAL_B' is REVOKED or inactive`.*

### 4. Execute a 2-of-N Multi-Signature Emergency Override
```powershell
Invoke-RestMethod -Method Post http://localhost:5000/portal/sign_and_submit -ContentType "application/json" -Body '{"official_id":"OFFICIAL_A","employee_id":"EMP1001","action":"ADMIN_OVERRIDE","extra":{"override_status":"OUT","co_official_id":"OFFICIAL_B"}}' | ConvertTo-Json -Depth 3
```
*Requires both OFFICIAL_A and OFFICIAL_B co-signatures to change employee status.*

---

## Phase 7: Simulating Attacks & Self-Healing in Terminal

### 1. Run the Standalone Cryptographic Tamper Attack Demonstration
```powershell
python demos/demo_crypto_tamper.py
```
*Demonstrates Attack 1 (modifying payload breaks BLAKE3 hash) and Attack 2 (re-hashing forward fails Ed448 signature check).*

### 2. Run the Multi-Node Tamper Detection & Nakamoto Healing Demo
```powershell
python demos/demo_tamper_heal.py
```
*Automatically boots 3 temporary nodes, corrupts Node 5001's disk WAL, detects the fork, and verifies Nakamoto longest-valid-chain healing.*

### 3. Corrupt Block #1 on Node 5001's Disk (Simulating Hacker / Bit-Rot)
```powershell
Invoke-RestMethod -Method Post http://localhost:5001/debug/tamper_local_block -ContentType "application/json" -Body '{"block_index": 1}'
```

### 4. Inspect Node 5001's Ledger to Show Corruption
```powershell
(Invoke-RestMethod http://localhost:5001/chain) | Select-Object index, hash, valid | Format-Table
```
*Notice Block #1 now shows `valid: False`.*

### 5. Trigger Nakamoto Consensus Auto-Healing on Node 5001
```powershell
Invoke-RestMethod -Method Post http://localhost:5001/nodes/resolve
```
*Node 5001 contacts honest peers, downloads authentic blocks, verifies signatures, and repairs its disk WAL.*

### 6. Verify Node 5001 is Restored to 100% Health
```powershell
(Invoke-RestMethod http://localhost:5001/chain) | Select-Object index, hash, valid | Format-Table
```
*All blocks show `valid: True` again.*

### 7. Simulate a Signature Forgery Attack
```powershell
Invoke-RestMethod -Method Post http://localhost:5000/debug/forge_and_broadcast -ContentType "application/json" -Body '{"employee_id":"EMP1003","action":"CHECK_IN","official_id":"OFFICIAL_A"}' | ConvertTo-Json -Depth 3
```
*Peers independently reject the forged block despite a mathematically consistent BLAKE3 hash.*

---

## Phase 8: Zero-Knowledge Privacy Proofs (ZKP) in Terminal

### 1. Generate a Zero-Knowledge Range Proof via REST API
```powershell
Invoke-RestMethod -Method Post http://localhost:5000/zkp/generate_proof -ContentType "application/json" -Body '{"employee_id":"EMP1001","threshold_hours":8.0,"simulated_hours":8.5}' | ConvertTo-Json -Depth 3
```
*Returns Pedersen Commitment $C = g^v h^r \pmod p$ and 12-bit CDS94 non-interactive range proof.*

### 2. Verify ZKP Shift Compliance via Python CLI in 1 Line
```powershell
python -c "import zkp_utils; p = zkp_utils.generate_compliance_proof(28800, 28800, 'EMP1001'); valid, msg = zkp_utils.verify_compliance_proof(p); print('ZKP Result:', valid, '| Reason:', msg)"
```
*Output: `ZKP Result: True | Reason: Shift duration verified >= 8.00h (CDS94 12-bit range proof).`*

### 3. Test Fraud Attempt (+5h Tampered Claim) Rejection in 1 Line
```powershell
python -c "import zkp_utils; p = zkp_utils.generate_compliance_proof(28800, 28800, 'EMP1001'); p['threshold_hours'] += 5.0; p['threshold'] += 18000; valid, msg = zkp_utils.verify_compliance_proof(p); print('Tamper Rejected?:', not valid, '| Msg:', msg)"
```
*Output: `Tamper Rejected?: True | Msg: Homomorphic range proof verification failed.`*

---

## Phase 9: SPV Merkle Proofs & Offline Certificate Verification

### 1. Fetch the SPV Merkle Inclusion Proof for Block #1
```powershell
Invoke-RestMethod http://localhost:5000/blocks/1/proof/0 | ConvertTo-Json -Depth 4
```
*Shows the transaction and sibling hashes verifying inclusion in $O(\log N)$ time.*

### 2. Verify the SPV Proof Cryptographically via API
```powershell
$proofData = Invoke-RestMethod http://localhost:5000/blocks/1/proof/0
Invoke-RestMethod -Method Post http://localhost:5000/verify_merkle_proof -ContentType "application/json" -Body ($proofData | ConvertTo-Json)
```
*Output: `valid: True`*

### 3. Export a Cryptographic SOC-2 Compliance Certificate to File
```powershell
Invoke-RestMethod http://localhost:5000/audit/certificate/EMP1001 | ConvertTo-Json -Depth 5 | Out-File -FilePath certificate_EMP1001.json -Encoding utf8
```

### 4. Verify the Certificate Offline Using Standalone CLI Verifier
* **From Exported JSON File:**
  ```powershell
  python verify_certificate.py certificate_EMP1001.json
  ```
* **Directly Querying Node 5000:**
  ```powershell
  python verify_certificate.py --employee EMP1001
  ```
*Verifies the BLAKE3 seal, Ed448 digital signatures, and Merkle root commitments without needing internet or running servers.*

---

## Phase 10: High-Throughput Concurrency & TPS Stress Benchmark

### 1. Run Live Mempool Concurrency Stress Test via API (25 Concurrent Tx)
* **PowerShell:**
  ```powershell
  Invoke-RestMethod -Method Post http://localhost:5000/benchmark/run -ContentType "application/json" -Body '{"count": 25}' | Format-List
  ```
* **curl.exe:**
  ```cmd
  curl.exe -X POST http://localhost:5000/benchmark/run -H "Content-Type: application/json" -d "{\"count\": 25}"
  ```
*Sample Output:*
```text
avg_mempool_latency_ms : 0.08
blocks_mined           : 1
duration_seconds       : 0.092
peak_tps               : 271.7
state_root             : 7f81a4b6c3d9...
success                : True
transactions_processed : 25
```

### 2. Run Multi-Threaded Standalone Benchmark Suite
```powershell
python benchmark_network.py --txs 30 --workers 5
```
*Simulates high-frequency concurrent badge scans across 5 parallel worker threads, measuring P50, P90, P99 latency percentiles and mempool queue absorption.*

---

## Phase 11: Cryptographic Employee Digital Identity Badges

### 1. Inspect Verifiable Digital Identity Badge for EMP1001
* **PowerShell:**
  ```powershell
  Invoke-RestMethod http://localhost:5000/employee/EMP1001/badge | ConvertTo-Json -Depth 3
  ```
* **curl.exe:**
  ```cmd
  curl.exe -s http://localhost:5000/employee/EMP1001/badge
  ```
*Outputs security clearance, live status, hours worked, latest block hash, and consensus algorithm.*

---

## Phase 12: Standalone Demo Scripts Quick-Runner

| Script | Purpose | Execution Command |
| :--- | :--- | :--- |
| **Interactive Terminal Showcase** | 11-step interactive color-coded menu | `powershell -ExecutionPolicy Bypass -File .\demo_showcase.ps1` |
| **P2P Network Walkthrough** | 5-step cluster verification script | `python demos/demo_network_walkthrough.py` |
| **Crypto & Tamper Resistance** | Mathematical proof of attack resistance | `python demos/demo_crypto_tamper.py` |
| **Governance & 2-of-N Multi-Sig** | Onboarding, CRL revocation, emergency multi-sig | `python demos/demo_governance.py` |
| **Tamper & Nakamoto Healing** | Multi-node disk corruption and self-healing | `python demos/demo_tamper_heal.py` |
| **Full Automated Test Suite** | 36 unit and integration tests | `python -m unittest discover tests` |
| **Security Audit Regression Suite**| Specific tests for audit vulnerabilities A-E | `python -m unittest tests/test_audit_fixes.py` |

---

## Quick Top-5 Presentation Cheat Sheet
*(Keep these 5 handy to quickly blow away your faculty during the live demo)*

| # | Action | Exact PowerShell Command |
| :- | :--- | :--- |
| **1** | **Check Cluster Health** | `[PSCustomObject]@{ Node5000 = (irm http://localhost:5000/chain).Length; Node5001 = (irm http://localhost:5001/chain).Length; Node5002 = (irm http://localhost:5002/chain).Length; StateRoot = (irm http://localhost:5000/state).state_root.Substring(0,18)+'...' }` |
| **2** | **View On-Disk Raw Ledger** | `Get-Content .\data\node_5000\chain.jsonl | ForEach-Object { $_ | ConvertFrom-Json } | Select-Object index, official_id, hash, state_root | ft -AutoSize` |
| **3** | **View Live World State** | `(irm http://localhost:5000/state).world_state.employees | ft -AutoSize` |
| **4** | **Corrupt & Heal Node 5001** | `irm -Method Post http://localhost:5001/debug/tamper_local_block -Body '{"block_index":1}' -ContentType "application/json"; irm -Method Post http://localhost:5001/nodes/resolve` |
| **5** | **Verify ZKP Math** | `python -c "import zkp_utils; p = zkp_utils.generate_compliance_proof(28800, 28800, 'EMP1001'); print('ZKP Verified:', zkp_utils.verify_compliance_proof(p)[0])"` |
