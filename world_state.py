"""
world_state.py — World State Database for IPLS (Hyperledger Fabric Pattern).

In enterprise blockchains like Hyperledger Fabric and Ethereum:
  • The LEDGER is an immutable, append-only chain of blocks (transaction history).
  • The WORLD STATE is a key-value store holding the CURRENT values of assets
    and entities (e.g. employee status, total hours worked, active officials).

Every block execution causes a deterministic state transition:
    WorldState_(n) = Apply(WorldState_(n-1), Block_n)

A cryptographic STATE ROOT HASH is computed via domain-keyed BLAKE3 over the
canonical state snapshot. This root is committed into every block header.
Every node verifies that its local state root matches the block's state root,
guaranteeing state consistency across all peers.
"""
import copy
import json
import hash_utils


class WorldState:
    def __init__(self, initial_personnel=None, initial_officials=None):
        self.employees = {}
        self.officials = {}
        self.meta = {
            "version": "1.0",
            "total_transactions": 0,
        }

        # Seed initial personnel registry
        if initial_personnel:
            for emp_id in initial_personnel:
                self.employees[emp_id] = {
                    "status": "OUT",
                    "last_check_in": None,
                    "last_check_out": None,
                    "total_seconds_worked": 0.0,
                    "department": "Engineering",
                    "registered_by": "SYSTEM",
                }

        # Seed initial officials registry
        if initial_officials:
            for oid in initial_officials:
                self.officials[oid] = {
                    "status": "ACTIVE",
                }

    def clone(self):
        """Deep copy of the current state for atomic dry-run validation."""
        cloned = WorldState()
        cloned.employees = copy.deepcopy(self.employees)
        cloned.officials = copy.deepcopy(self.officials)
        cloned.meta = copy.deepcopy(self.meta)
        return cloned

    # ── Official Management ──────────────────────────────────────────────────

    def is_official_active(self, official_id: str) -> bool:
        off = self.officials.get(official_id)
        return off is not None and off.get("status") == "ACTIVE"

    def register_official(self, official_id: str):
        self.officials[official_id] = {"status": "ACTIVE"}

    def revoke_official(self, official_id: str):
        if official_id in self.officials:
            self.officials[official_id]["status"] = "REVOKED"

    def is_official_revoked(self, official_id: str) -> bool:
        off = self.officials.get(official_id)
        return off is not None and off.get("status") == "REVOKED"

    # ── Employee Management ──────────────────────────────────────────────────

    def is_employee_registered(self, employee_id: str) -> bool:
        return employee_id in self.employees

    def get_employee(self, employee_id: str) -> dict:
        return self.employees.get(employee_id)

    def register_employee(self, employee_id: str, department="Operations", registered_by="SYSTEM"):
        self.employees[employee_id] = {
            "status": "OUT",
            "last_check_in": None,
            "last_check_out": None,
            "total_seconds_worked": 0.0,
            "department": department,
            "registered_by": registered_by,
        }

    def record_check_in(self, employee_id: str, timestamp: float):
        emp = self.employees[employee_id]
        emp["status"] = "IN"
        emp["last_check_in"] = timestamp

    def record_check_out(self, employee_id: str, timestamp: float):
        emp = self.employees[employee_id]
        emp["status"] = "OUT"
        emp["last_check_out"] = timestamp
        if emp.get("last_check_in") and timestamp > emp["last_check_in"]:
            shift_seconds = timestamp - emp["last_check_in"]
            emp["total_seconds_worked"] += round(shift_seconds, 2)

    def increment_tx_counter(self):
        self.meta["total_transactions"] += 1

    # ── Canonical Serialization & State Root ─────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "employees": self.employees,
            "officials": self.officials,
            "meta": self.meta,
        }

    def canonical_bytes(self) -> bytes:
        """Deterministic byte representation with sorted keys."""
        return json.dumps(self.to_dict(), sort_keys=True).encode()

    def compute_state_root(self) -> str:
        """
        Compute the 256-bit BLAKE3 domain-keyed State Root hash of this World State.
        Committed to the block header to prove all nodes share identical database state.
        """
        return hash_utils.compute_state_hash(self.canonical_bytes())
