"""
contract.py — Enterprise Chaincode Engine for IPLS (Hyperledger Fabric Pattern).

This module implements the deterministic Smart Contract / Chaincode layer:
  1. RECORD_ATTENDANCE (CHECK_IN / CHECK_OUT)
     - State machine validation (no double check-in, no check-out without check-in)
     - Shift duration calculation & excessive shift alerts (>16h)
  2. REGISTER_EMPLOYEE
     - On-chain onboarding of personnel with department metadata
  3. REVOKE_OFFICIAL (On-Chain Key Revocation / CRL)
     - Official credentials can be permanently revoked on-chain
     - Any subsequent blocks/transactions signed by revoked official are rejected
  4. ADMIN_OVERRIDE (Multi-Signature 2-of-N Governance)
     - Retroactive status corrections require co-signatures from TWO distinct active officials
"""
import json
from world_state import WorldState


class ContractViolation(Exception):
    """Raised when a proposed transaction violates Chaincode rules."""
    pass


class ChaincodeEngine:
    """
    Enterprise Chaincode implementation that enforces business rules and
    transitions the World State.
    """

    def __init__(self, initial_personnel=None, initial_officials=None, official_public_keys=None):
        self.world_state = WorldState(initial_personnel, initial_officials)
        self.official_public_keys = dict(official_public_keys) if official_public_keys else {}
        if not self.official_public_keys:
            try:
                import crypto_utils as cu
                with open("network_config.json") as f:
                    cfg = json.load(f)
                self.official_public_keys = {
                    k: cu.public_key_from_str(v if isinstance(v, str) else v.get("public_key"))
                    for k, v in cfg.get("officials", {}).items()
                }
            except Exception:
                pass

    @staticmethod
    def compute_override_co_sign_bytes(emp_id: str, override_status: str, primary_official: str, co_official: str, ts: float) -> bytes:
        """Canonical message that a co-signing official must sign with Ed448 for 2-of-N overrides."""
        return json.dumps({
            "action": "ADMIN_OVERRIDE_CO_SIGN",
            "co_official": co_official,
            "employee_id": emp_id,
            "override_status": override_status,
            "primary_official": primary_official,
            "timestamp": ts,
        }, sort_keys=True).encode()

    # ── High-Level Chaincode Dispatcher ──────────────────────────────────────

    def execute_transaction(self, state: WorldState, action: str, data: dict, official_id: str) -> str:
        """
        Deterministically validate and apply a transaction to `state`.
        Returns the new 64-char BLAKE3 State Root Hash.
        Raises ContractViolation on any illegal state transition.
        """
        import math

        if not isinstance(data, dict):
            raise ContractViolation("Transaction data payload must be a dictionary")
        if not isinstance(official_id, str) or not official_id.strip():
            raise ContractViolation("Transaction official_id must be a non-empty string")
        if not isinstance(action, str) or not action.strip():
            raise ContractViolation("Transaction action must be a non-empty string")

        # Rule 1: Originating official must be registered and ACTIVE
        if not state.is_official_active(official_id):
            raise ContractViolation(f"Official '{official_id}' is not an active, authorized official (revoked or unknown)")

        action = action.upper()
        emp_id = data.get("employee_id")
        ts = data.get("timestamp", 0)

        # Invariant: Timestamp must be a finite, positive number within reasonable bounds (Fixes Finding E)
        if not isinstance(ts, (int, float)) or isinstance(ts, bool) or not math.isfinite(ts) or ts <= 0:
            raise ContractViolation(f"Invalid transaction timestamp '{ts}'. Must be a finite, positive number.")
        if ts > 1e12:
            raise ContractViolation(f"Transaction timestamp '{ts}' exceeds reasonable bounds (must be <= 1e12).")

        # Replay protection: check transaction ID if provided
        tx_id = data.get("tx_id")
        if tx_id:
            if state.is_tx_executed(tx_id):
                raise ContractViolation(f"Replay detected: transaction '{tx_id}' has already been executed on-chain")
            state.mark_tx_executed(tx_id)

        if action in ("CHECK_IN", "CHECK_OUT"):
            self._handle_attendance(state, emp_id, action, ts, official_id)

        elif action == "REGISTER_EMPLOYEE":
            dept = data.get("department", "Operations")
            self._handle_register_employee(state, emp_id, dept, official_id)

        elif action == "REVOKE_OFFICIAL":
            target_official = data.get("target_official")
            self._handle_revoke_official(state, target_official, official_id)

        elif action == "ADMIN_OVERRIDE":
            self._handle_override(state, emp_id, ts, official_id, data)

        else:
            raise ContractViolation(f"Unknown chaincode action '{action}'")

        state.increment_tx_counter()
        return state.compute_state_root()

    # ── Action Handlers ──────────────────────────────────────────────────────

    def _handle_attendance(self, state: WorldState, emp_id: str, action: str, ts: float, official_id: str):
        if not emp_id or not isinstance(emp_id, str):
            raise ContractViolation("Missing or invalid 'employee_id' in attendance transaction")
        if not state.is_employee_registered(emp_id):
            raise ContractViolation(f"'{emp_id}' is not in the personnel registry")

        emp = state.get_employee(emp_id)
        current_status = emp.get("status", "OUT")
        last_action_ts = emp.get("last_action_timestamp")

        # Invariant: Strict per-employee timestamp monotonicity & replay protection (Fixes Finding D)
        if last_action_ts is not None and ts <= last_action_ts:
            raise ContractViolation(
                f"Replay or out-of-order transaction for '{emp_id}': timestamp ({ts}) "
                f"must be strictly greater than last action timestamp ({last_action_ts})"
            )

        if action == "CHECK_IN":
            if current_status == "IN":
                raise ContractViolation(f"'{emp_id}' is already checked in")

            last_out = emp.get("last_check_out")
            if last_out is not None and ts <= last_out:
                raise ContractViolation(
                    f"Replay detected: check-in timestamp ({ts}) must be strictly greater than last check-out ({last_out})"
                )

            state.record_check_in(emp_id, ts)
            emp["last_action_timestamp"] = ts

        elif action == "CHECK_OUT":
            if current_status == "OUT":
                raise ContractViolation(f"'{emp_id}' is not checked in")
            
            last_in = emp.get("last_check_in")
            if last_in is not None and ts <= last_in:
                raise ContractViolation(
                    f"Check-out timestamp ({ts}) must be strictly greater than check-in ({last_in})"
                )

            # Check shift duration warning (>16 hours = 57,600s)
            if last_in and (ts - last_in) > 57600:
                emp["shift_warning"] = "EXCESSIVE_SHIFT_DURATION_EXCEEDS_16H"

            state.record_check_out(emp_id, ts)
            emp["last_action_timestamp"] = ts

    def _handle_register_employee(self, state: WorldState, emp_id: str, dept: str, official_id: str):
        if not emp_id:
            raise ContractViolation("Missing 'employee_id' for registration")
        if state.is_employee_registered(emp_id):
            raise ContractViolation(f"Employee '{emp_id}' is already registered")
        state.register_employee(emp_id, department=dept, registered_by=official_id)

    def _handle_revoke_official(self, state: WorldState, target_official: str, official_id: str):
        if not target_official:
            raise ContractViolation("Missing 'target_official' to revoke")
        if target_official == official_id:
            raise ContractViolation("An official cannot revoke their own credentials")
        if not state.is_official_active(target_official):
            raise ContractViolation(f"Official '{target_official}' is already revoked or does not exist")
        state.revoke_official(target_official)

    def _handle_override(self, state: WorldState, emp_id: str, ts: float, official_id: str, data: dict):
        """
        Multi-Signature (2-of-N) emergency override governance.
        Requires cryptographic co-signature from a second distinct active official.
        """
        target_status = data.get("override_status", "OUT")
        if target_status not in ("IN", "OUT"):
            raise ContractViolation(f"Invalid override_status '{target_status}'. Must be strictly 'IN' or 'OUT'")

        co_official = data.get("co_official_id")
        co_signature = data.get("co_signature")

        if not co_official or not co_signature:
            raise ContractViolation(
                "ADMIN_OVERRIDE requires 2-of-N Multi-Signature: 'co_official_id' and 'co_signature' must be provided"
            )
        if co_official == official_id:
            raise ContractViolation("Co-signing official must be a DIFFERENT Higher Official")
        if not state.is_official_active(co_official):
            raise ContractViolation(f"Co-signing official '{co_official}' is not active or authorized")

        # Cryptographically verify the co-signature over the canonical override payload
        co_pubkey = self.official_public_keys.get(co_official)
        if co_pubkey:
            import crypto_utils as cu
            co_bytes = self.compute_override_co_sign_bytes(emp_id, target_status, official_id, co_official, ts)
            if not cu.verify_signature(co_pubkey, co_bytes, co_signature):
                raise ContractViolation(
                    f"Cryptographic verification failed: Ed448 co-signature from '{co_official}' is invalid"
                )
        else:
            raise ContractViolation(f"Public key for co-signing official '{co_official}' is not loaded")

        if not state.is_employee_registered(emp_id):
            raise ContractViolation(f"'{emp_id}' is not in the personnel registry")

        emp = state.get_employee(emp_id)
        last_action_ts = emp.get("last_action_timestamp")
        if last_action_ts is not None and ts <= last_action_ts:
            raise ContractViolation(
                f"Replay or out-of-order override for '{emp_id}': timestamp ({ts}) "
                f"must be strictly greater than last action timestamp ({last_action_ts})"
            )
        emp["last_action_timestamp"] = ts

        # Shift accounting reconciliation
        if target_status == "OUT" and emp.get("status") == "IN" and emp.get("last_check_in"):
            if ts >= emp["last_check_in"]:
                worked = ts - emp["last_check_in"]
                emp["total_seconds_worked"] = emp.get("total_seconds_worked", 0.0) + worked

        emp["status"] = target_status
        emp["last_override"] = {
            "authorized_by": [official_id, co_official],
            "timestamp": ts,
            "target_status": target_status,
        }
        if target_status == "IN":
            emp["last_check_in"] = ts
        else:
            emp["last_check_out"] = ts


# Backward compatibility alias
ContractEngine = ChaincodeEngine
