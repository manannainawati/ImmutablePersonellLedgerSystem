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
from world_state import WorldState


class ContractViolation(Exception):
    """Raised when a proposed transaction violates Chaincode rules."""
    pass


class ChaincodeEngine:
    """
    Enterprise Chaincode implementation that enforces business rules and
    transitions the World State.
    """

    def __init__(self, initial_personnel=None, initial_officials=None):
        self.world_state = WorldState(initial_personnel, initial_officials)

    # ── High-Level Chaincode Dispatcher ──────────────────────────────────────

    def execute_transaction(self, state: WorldState, action: str, data: dict, official_id: str) -> str:
        """
        Deterministically validate and apply a transaction to `state`.
        Returns the new 64-char BLAKE3 State Root Hash.
        Raises ContractViolation on any illegal state transition.
        """
        # Rule 1: Originating official must be registered and ACTIVE
        if not state.is_official_active(official_id):
            raise ContractViolation(f"Official '{official_id}' is not an active, authorized official (revoked or unknown)")

        action = action.upper()
        emp_id = data.get("employee_id")
        ts = data.get("timestamp", 0)

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
        if not emp_id:
            raise ContractViolation("Missing 'employee_id' in attendance transaction")
        if not state.is_employee_registered(emp_id):
            raise ContractViolation(f"'{emp_id}' is not in the personnel registry")

        emp = state.get_employee(emp_id)
        current_status = emp.get("status", "OUT")

        if action == "CHECK_IN":
            if current_status == "IN":
                raise ContractViolation(f"'{emp_id}' is already checked in")
            state.record_check_in(emp_id, ts)

        elif action == "CHECK_OUT":
            if current_status == "OUT":
                raise ContractViolation(f"'{emp_id}' is not checked in")
            
            # Check shift duration warning (>16 hours = 57,600s)
            last_in = emp.get("last_check_in")
            if last_in and (ts - last_in) > 57600:
                emp["shift_warning"] = "EXCESSIVE_SHIFT_DURATION_EXCEEDS_16H"

            state.record_check_out(emp_id, ts)

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
        Requires co-signature from a second distinct active official.
        """
        target_status = data.get("override_status", "OUT")
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

        if not state.is_employee_registered(emp_id):
            raise ContractViolation(f"'{emp_id}' is not in the personnel registry")

        emp = state.get_employee(emp_id)
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
