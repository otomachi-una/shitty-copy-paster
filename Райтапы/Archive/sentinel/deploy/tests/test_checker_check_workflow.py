import contextlib
import http.server
import io
import json
import os
import sys
import threading
import unittest
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
CHECKER_DIR = ROOT / "checkers" / "sentinel_aml"
sys.path.insert(0, str(CHECKER_DIR))

import checker  # noqa: E402
import checker_lib  # noqa: E402


SECRET = "check-workflow-secret"


class FakeCheckHandler(http.server.BaseHTTPRequestHandler):
    server_version = "FakeSentinelAMLCheck/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.handle_request(self)

    def do_POST(self):
        self.server.handle_request(self)

    def log_message(self, format, *args):
        return


class FakeCheckServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(
        self,
        *,
        fail_route=None,
        fail_status=500,
        fail_body=None,
        omit_dedup_candidate=False,
        leak_private_merge_preview=False,
        audit_available=True,
        omit_timeline_note_event=False,
        leak_private_timeline=False,
        graph_available=True,
        leak_private_graph=False,
        export_available=True,
        leak_private_export=False,
        network_available=True,
        leak_private_network=False,
        omit_network_room=False,
        network_room_list_delay=0,
    ):
        super().__init__(("127.0.0.1", 0), FakeCheckHandler)
        self.requests = []
        self.responses = []
        self.fail_route = fail_route
        self.fail_status = fail_status
        self.fail_body = fail_body or {"error": "forced_failure"}
        self.login_token = "check-login-token"
        self.next_customer_id = 1201
        self.next_account_id = 2201
        self.next_transaction_id = 3201
        self.next_alert_id = 4201
        self.next_case_id = 5201
        self.next_note_id = 6201
        self.next_export_id = 7201
        self.next_edd_id = 8201
        self.next_room_id = 9201
        self.customers = {}
        self.accounts = {}
        self.transactions = {}
        self.alerts = {}
        self.cases = {}
        self.notes = {}
        self.edd_records = {}
        self.exports = {}
        self.network_rooms = {}
        self.network_room_cases = {}
        self.omit_dedup_candidate = omit_dedup_candidate
        self.leak_private_merge_preview = leak_private_merge_preview
        self.audit_available = audit_available
        self.omit_timeline_note_event = omit_timeline_note_event
        self.leak_private_timeline = leak_private_timeline
        self.graph_available = graph_available
        self.leak_private_graph = leak_private_graph
        self.last_timeline_events = []
        self.export_available = export_available
        self.leak_private_export = leak_private_export
        self.network_available = network_available
        self.leak_private_network = leak_private_network
        self.omit_network_room = omit_network_room
        self.network_room_list_delay = network_room_list_delay

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(2.0)
        return request, client_address

    @property
    def url(self):
        host, port = self.server_address
        return f"http://{host}:{port}"

    def handle_request(self, handler):
        length = int(handler.headers.get("Content-Length", "0"))
        raw_body = handler.rfile.read(length) if length else b""
        body = json.loads(raw_body.decode("utf-8")) if raw_body else None
        self.requests.append(
            {
                "method": handler.command,
                "path": handler.path,
                "body": body,
                "authorization": handler.headers.get("Authorization", ""),
            }
        )

        if handler.path == self.fail_route:
            self.write_json(handler, self.fail_status, self.fail_body)
            return

        if (handler.command, handler.path) == ("GET", "/healthz"):
            self.write_json(handler, 200, {"status": "ok"})
            return
        if (handler.command, handler.path) == ("POST", "/api/auth/register"):
            self.write_json(handler, 201, {"session": {"token": "register-token"}})
            return
        if (handler.command, handler.path) == ("POST", "/api/auth/login"):
            self.write_json(handler, 200, {"session": {"token": self.login_token}})
            return
        if (handler.command, handler.path) == ("POST", "/api/customers"):
            self._create_customer(handler, body or {})
            return
        if handler.command == "GET" and handler.path.startswith("/api/customers/"):
            parts = handler.path.strip("/").split("/")
            if len(parts) == 3:
                self._get_customer(handler, int(parts[2]))
                return
            if len(parts) == 4 and parts[3] == "accounts":
                self._list_accounts(handler, int(parts[2]))
                return
            if len(parts) == 4 and parts[3] == "transactions":
                self._list_transactions(handler, int(parts[2]))
                return
            if len(parts) == 4 and parts[3] == "edd":
                self._get_edd(handler, int(parts[2]))
                return
        if handler.command == "POST" and handler.path.startswith("/api/customers/") and handler.path.endswith("/accounts"):
            customer_id = int(handler.path.strip("/").split("/")[2])
            self._create_account(handler, customer_id, body or {})
            return
        if (handler.command, handler.path) == ("POST", "/api/transactions"):
            self._create_transaction(handler, body or {})
            return
        if handler.command == "GET" and handler.path.startswith("/api/transactions/"):
            self._get_transaction(handler, int(handler.path.rsplit("/", 1)[1]))
            return
        if handler.command == "POST" and handler.path.startswith("/api/customers/") and handler.path.endswith("/edd"):
            customer_id = int(handler.path.strip("/").split("/")[2])
            self._create_edd(handler, customer_id, body or {})
            return
        if handler.command == "GET" and handler.path.startswith("/api/graph/entities/") and self.graph_available:
            self._handle_graph(handler)
            return
        if handler.command == "GET" and handler.path == "/api/network/rooms" and self.network_available:
            self._list_network_rooms(handler)
            return
        if handler.command == "GET" and handler.path.startswith("/api/network/rooms/") and self.network_available:
            self._handle_network_room(handler)
            return
        if (handler.command, handler.path) == ("GET", "/api/alerts/queue"):
            self.write_json(handler, 200, {"alerts": list(self.alerts.values())})
            return
        if handler.command == "POST" and handler.path.startswith("/api/alerts/") and handler.path.endswith("/claim"):
            self.write_json(handler, 200, {"id": int(handler.path.strip("/").split("/")[2])})
            return
        if handler.command == "POST" and handler.path.startswith("/api/alerts/") and handler.path.endswith("/case"):
            alert_id = int(handler.path.strip("/").split("/")[2])
            self._create_case(handler, alert_id, body or {})
            return
        if handler.command == "POST" and handler.path.startswith("/api/cases/") and handler.path.endswith("/notes"):
            case_id = int(handler.path.strip("/").split("/")[2])
            self._create_note(handler, case_id, body or {})
            return
        if handler.command == "POST" and handler.path.startswith("/api/cases/") and handler.path.endswith("/exports") and self.export_available:
            case_id = int(handler.path.strip("/").split("/")[2])
            self._create_export(handler, case_id, body or {})
            return
        if handler.command == "GET" and handler.path.startswith("/api/exports/") and self.export_available:
            export_id = int(handler.path.rsplit("/", 1)[1])
            self._get_export(handler, export_id)
            return
        if handler.command == "GET" and handler.path.startswith("/api/cases/") and handler.path.endswith("/timeline") and self.audit_available:
            case_id = int(handler.path.strip("/").split("/")[2])
            self._list_timeline(handler, case_id)
            return
        if handler.command == "GET" and handler.path.startswith("/api/cases/") and handler.path.endswith("/notes"):
            case_id = int(handler.path.strip("/").split("/")[2])
            self._list_notes(handler, case_id)
            return
        if handler.command == "GET" and handler.path.startswith("/api/cases/") and "/duplicates" in handler.path:
            parts = handler.path.strip("/").split("/")
            source_case_id = int(parts[2])
            if len(parts) == 4:
                self._list_duplicates(handler, source_case_id)
                return
            if len(parts) == 6 and parts[5] == "merge-preview":
                self._merge_preview(handler, source_case_id, int(parts[4]))
                return
        self.write_json(handler, 404, {"error": "not_found"})

    def _create_customer(self, handler, body):
        customer_id = self.next_customer_id
        self.next_customer_id += 1
        customer = {
            "id": customer_id,
            "display_name": body.get("display_name", ""),
            "customer_type": body.get("customer_type", "organization"),
            "country": body.get("country", "US"),
            "registration_number": body.get("registration_number", ""),
            "risk_level": body.get("risk_level", "low"),
            "entity_hint": body.get("entity_hint", ""),
            "status": "active",
        }
        self.customers[customer_id] = customer
        self.write_json(handler, 201, customer)

    def _get_customer(self, handler, customer_id):
        self.write_json(handler, 200 if customer_id in self.customers else 404, self.customers.get(customer_id, {"error": "not_found"}))

    def _create_account(self, handler, customer_id, body):
        account_id = self.next_account_id
        self.next_account_id += 1
        account = {
            "id": account_id,
            "customer_id": customer_id,
            "iban_like": body.get("iban_like", ""),
            "currency": body.get("currency", "USD"),
            "status": "active",
        }
        self.accounts[account_id] = account
        self.write_json(handler, 201, account)

    def _list_accounts(self, handler, customer_id):
        self.write_json(handler, 200, {"accounts": [account for account in self.accounts.values() if account["customer_id"] == customer_id]})

    def _create_transaction(self, handler, body):
        transaction_id = self.next_transaction_id
        self.next_transaction_id += 1
        account_id = body.get("account_id")
        account = self.accounts[account_id]
        transaction = {
            "id": transaction_id,
            "account_id": account_id,
            "counterparty_name": body.get("counterparty_name", ""),
            "counterparty_country": body.get("counterparty_country", "US"),
            "counterparty_fingerprint": body.get("counterparty_fingerprint", ""),
            "amount": body.get("amount", "0.00"),
            "currency": body.get("currency", "USD"),
            "direction": body.get("direction", "outbound"),
            "purpose": body.get("purpose", "invoice"),
            "trace_id": body.get("trace_id", ""),
            "risk_score": 80,
        }
        self.transactions[transaction_id] = transaction
        alert_id = self.next_alert_id
        self.next_alert_id += 1
        self.alerts[alert_id] = {
            "id": alert_id,
            "transaction_id": transaction_id,
            "customer_id": account["customer_id"],
            "typology_hint": "counterparty-watchlist",
        }
        self.write_json(handler, 201, transaction)

    def _get_transaction(self, handler, transaction_id):
        self.write_json(handler, 200 if transaction_id in self.transactions else 404, self.transactions.get(transaction_id, {"error": "not_found"}))

    def _list_transactions(self, handler, customer_id):
        account_ids = {account_id for account_id, account in self.accounts.items() if account["customer_id"] == customer_id}
        self.write_json(
            handler,
            200,
            {"transactions": [transaction for transaction in self.transactions.values() if transaction["account_id"] in account_ids]},
        )

    def _create_case(self, handler, alert_id, body):
        case_id = self.next_case_id
        self.next_case_id += 1
        alert = self.alerts[alert_id]
        investigation_case = {
            "id": case_id,
            "alert_id": alert_id,
            "customer_id": alert["customer_id"],
            "public_summary": body.get("public_summary", ""),
            "dedup_hint": body.get("dedup_hint", ""),
            "typology_hint": alert["typology_hint"],
            "risk_score": 80,
            "status": "OPEN",
        }
        self.cases[case_id] = investigation_case
        self._materialize_network_rooms()
        self.write_json(handler, 201, investigation_case)

    def _create_note(self, handler, case_id, body):
        note_id = self.next_note_id
        self.next_note_id += 1
        note = {"id": note_id, "case_id": case_id, "visibility": body.get("visibility", "private"), "body": body.get("body", "")}
        self.notes[note_id] = note
        self.write_json(handler, 201, note)

    def _list_notes(self, handler, case_id):
        self.write_json(handler, 200, {"notes": [note for note in self.notes.values() if note["case_id"] == case_id]})

    def _create_edd(self, handler, customer_id, body):
        edd_id = self.next_edd_id
        self.next_edd_id += 1
        record = {
            "id": edd_id,
            "customer_id": customer_id,
            "source_of_funds": body.get("source_of_funds", ""),
            "risk_rationale": body.get("risk_rationale", ""),
            "confidential_comment": body.get("confidential_comment", ""),
            "review_status": body.get("review_status", "DRAFT"),
            "created_at": "2026-09-01T00:00:05Z",
            "updated_at": "2026-09-01T00:00:06Z",
        }
        self.edd_records[customer_id] = record
        self.write_json(handler, 201, record)

    def _get_edd(self, handler, customer_id):
        record = self.edd_records.get(customer_id)
        self.write_json(handler, 200 if record else 404, record or {"error": "not_found"})

    def _list_timeline(self, handler, case_id):
        events = [
            {
                "id": 1,
                "object_type": "case",
                "object_id": case_id,
                "event_type": "created",
                "public_message": "case created",
                "changes": [{"field": "status", "new": "OPEN", "redacted": False}],
                "created_at": "2026-09-01T00:00:00Z",
                "visibility_scope": "owner",
            }
        ]
        notes = [note for note in self.notes.values() if note["case_id"] == case_id]
        if notes and not self.omit_timeline_note_event:
            note_event = {
                "id": 2,
                "object_type": "case_note",
                "object_id": notes[-1]["id"],
                "event_type": "created",
                "public_message": "case note created",
                "changes": [{"field": "restricted_field", "new": "[redacted]", "redacted": True}],
                "created_at": "2026-09-01T00:00:01Z",
                "visibility_scope": "owner",
            }
            if self.leak_private_timeline:
                note_event["changes"][0]["new"] = notes[-1]["body"]
            events.append(note_event)
        self.last_timeline_events = events
        self.write_json(handler, 200, {"events": events})

    def _timeline_events_for_test(self):
        return self.last_timeline_events

    def _list_duplicates(self, handler, source_case_id):
        self.write_json(handler, 200, {"candidates": self._dedup_candidates(source_case_id)})

    def _merge_preview(self, handler, source_case_id, candidate_case_id):
        candidate = next((item for item in self._dedup_candidates(source_case_id) if item["case_id"] == candidate_case_id), None)
        if candidate is None:
            self.write_json(handler, 404, {"error": "not_found"})
            return
        if self.leak_private_merge_preview:
            candidate = dict(candidate)
            candidate["body"] = "foreign-private-body"
        self.write_json(handler, 200, {"source_case_id": source_case_id, "candidate": candidate})

    def _create_export(self, handler, case_id, body):
        if case_id not in self.cases:
            self.write_json(handler, 404, {"error": "not_found"})
            return
        export_id = self.next_export_id
        self.next_export_id += 1
        export = {
            "id": export_id,
            "root_case_id": case_id,
            "purpose": body.get("purpose", "case_review"),
            "status": "GENERATED",
            "redaction_policy": "public_redacted",
            "bundle": self._export_bundle(case_id, body.get("purpose", "case_review")),
            "created_at": "2026-09-01T00:00:07Z",
            "updated_at": "2026-09-01T00:00:08Z",
            "expires_at": "2026-09-02T00:00:07Z",
        }
        if self.leak_private_export:
            export["bundle"]["root_case"]["body"] = next(iter(self.notes.values()), {"body": "private-body"})["body"]
        self.exports[export_id] = export
        self.write_json(handler, 201, export)

    def _get_export(self, handler, export_id):
        export = self.exports.get(export_id)
        self.write_json(handler, 200 if export else 404, export or {"error": "not_found"})

    def _export_bundle(self, case_id, purpose):
        case = self.cases[case_id]
        edd = self.edd_records.get(case["customer_id"])
        audit_summaries = [
            {
                "event_id": 1,
                "object_type": "case_note",
                "object_id": next(iter(self.notes.values()), {"id": 1})["id"],
                "event_type": "created",
                "public_message": "case note created",
                "changed_fields": ["restricted_field", "visibility"],
                "created_at": "2026-09-01T00:00:09Z",
            }
        ]
        edd_summaries = []
        if edd:
            edd_summaries.append(
                {
                    "record_id": edd["id"],
                    "customer_id": edd["customer_id"],
                    "review_status": edd["review_status"],
                    "risk_tags": ["risk_level:medium"],
                    "created_at": edd["created_at"],
                    "updated_at": edd["updated_at"],
                }
            )
        return {
            "purpose": purpose,
            "redaction_policy": "public_redacted",
            "generated_at": "2026-09-01T00:00:10Z",
            "root_case": self._export_case_shell(case),
            "linked_cases": [],
            "audit_summaries": audit_summaries,
            "edd_summaries": edd_summaries,
            "items": [
                {
                    "item_type": "root_case",
                    "object_type": "case",
                    "object_id": case_id,
                    "relation": "root",
                    "redaction_policy": "public_redacted",
                }
            ],
        }

    def _export_case_shell(self, case):
        return {
            "case_id": case["id"],
            "customer_id": case["customer_id"],
            "status": case["status"],
            "public_summary": case["public_summary"],
            "risk_score": case["risk_score"],
            "typology_hint": case["typology_hint"],
            "created_at": "2026-09-01T00:00:11Z",
            "updated_at": "2026-09-01T00:00:12Z",
        }

    def _dedup_candidates(self, source_case_id):
        if self.omit_dedup_candidate:
            return []
        source = self.cases[source_case_id]
        result = []
        for case_id, candidate in self.cases.items():
            if case_id == source_case_id or candidate.get("dedup_hint") != source.get("dedup_hint"):
                continue
            result.append(
                {
                    "case_id": case_id,
                    "public_summary": candidate["public_summary"],
                    "risk_tags": ["risk_level:medium", "typology:counterparty-watchlist"],
                    "overlap_score": 95,
                    "match_explanation": "shared_dedup_hint",
                }
            )
        return result

    def _handle_graph(self, handler):
        rest = handler.path.removeprefix("/api/graph/entities/")
        parts = rest.split("/")
        entity_hint = unquote(parts[0])
        if len(parts) == 1:
            self._graph_entity(handler, entity_hint)
            return
        if len(parts) == 2 and parts[1] == "related-cases":
            self._graph_related_cases(handler, entity_hint)
            return
        self.write_json(handler, 404, {"error": "not_found"})

    def _graph_entity(self, handler, entity_hint):
        customer_ids = [customer_id for customer_id, customer in self.customers.items() if customer.get("entity_hint") == entity_hint]
        case_count = sum(1 for case in self.cases.values() if case.get("customer_id") in customer_ids)
        response = {
            "entity_hint": entity_hint,
            "relation_type": "shared_entity_hint",
            "customer_count": len(customer_ids),
            "case_count": case_count,
            "highest_risk": 80,
            "risk_tags": ["typology:counterparty-watchlist"],
            "updated_at": "2026-09-01T00:00:02Z",
        }
        if self.leak_private_graph:
            response["confidential_comment"] = "graph-private-leak"
        self.write_json(handler, 200 if customer_ids else 404, response if customer_ids else {"error": "not_found"})

    def _graph_related_cases(self, handler, entity_hint):
        customer_ids = {customer_id for customer_id, customer in self.customers.items() if customer.get("entity_hint") == entity_hint}
        cases = []
        for case in self.cases.values():
            customer_id = case.get("customer_id")
            if customer_id not in customer_ids:
                continue
            customer = self.customers[customer_id]
            cases.append(
                {
                    "case_id": case["id"],
                    "customer_id": customer_id,
                    "entity_hint": entity_hint,
                    "display_name": customer["display_name"],
                    "country": customer["country"],
                    "status": case["status"],
                    "public_summary": case["public_summary"],
                    "risk_score": case["risk_score"],
                    "typology_hint": case["typology_hint"],
                    "created_at": "2026-09-01T00:00:03Z",
                    "updated_at": "2026-09-01T00:00:04Z",
                }
            )
        if self.leak_private_graph and cases:
            cases[0]["body"] = "graph-related-private-body"
        self.write_json(handler, 200, {"cases": cases})

    def _materialize_network_rooms(self):
        if self.omit_network_room:
            return
        cases_by_entity = {}
        for case in self.cases.values():
            customer = self.customers.get(case["customer_id"])
            if not customer:
                continue
            cases_by_entity.setdefault(customer["entity_hint"], []).append(case)
        for entity_hint, cases in cases_by_entity.items():
            if len(cases) < 2:
                continue
            room_key = f"{entity_hint}:counterparty-watchlist"
            existing = next((room for room in self.network_rooms.values() if room["room_key"] == room_key), None)
            if existing is None:
                room_id = self.next_room_id
                self.next_room_id += 1
                self.network_rooms[room_id] = {
                    "id": room_id,
                    "room_key": room_key,
                    "entity_hint": entity_hint,
                    "typology_hint": "counterparty-watchlist",
                    "status": "OPEN",
                    "public_summary": f"Network room for {entity_hint}",
                    "public_risk_tags": ["typology:counterparty-watchlist"],
                    "case_count": 0,
                    "participant_count": 1,
                    "created_at": "2026-09-01T00:00:13Z",
                    "updated_at": "2026-09-01T00:00:14Z",
                }
                existing = self.network_rooms[room_id]
            self.network_room_cases[existing["id"]] = [case["id"] for case in cases]
            existing["case_count"] = len(cases)

    def _list_network_rooms(self, handler):
        if self.network_room_list_delay > 0:
            self.network_room_list_delay -= 1
            self.write_json(handler, 200, {"rooms": []})
            return
        rooms = [dict(room) for room in self.network_rooms.values()]
        if self.leak_private_network and rooms:
            rooms[0]["confidential_comment"] = "network-private-leak"
        self.write_json(handler, 200, {"rooms": rooms})

    def _handle_network_room(self, handler):
        parts = handler.path.strip("/").split("/")
        room_id = int(parts[3])
        if len(parts) == 5 and parts[4] == "dossier":
            self._network_room_dossier(handler, room_id)
            return
        self.write_json(handler, 404, {"error": "not_found"})

    def _network_room_dossier(self, handler, room_id):
        room = self.network_rooms.get(room_id)
        if not room:
            self.write_json(handler, 404, {"error": "not_found"})
            return
        cases = []
        for case_id in self.network_room_cases.get(room_id, []):
            case = self.cases[case_id]
            cases.append(
                {
                    "case_id": case["id"],
                    "customer_id": case["customer_id"],
                    "owned_by_requester": True,
                    "status": case["status"],
                    "public_summary": case["public_summary"],
                    "risk_score": case["risk_score"],
                    "typology_hint": case["typology_hint"],
                    "public_risk_tags": ["typology:counterparty-watchlist"],
                    "scope_coverage_complete": True,
                    "created_at": "2026-09-01T00:00:15Z",
                    "updated_at": "2026-09-01T00:00:16Z",
                }
            )
        dossier = {
            "room": dict(room),
            "cases": cases,
            "scope_policy": "case_reference_scope",
            "coverage_policy": "summary_coverage",
        }
        if self.leak_private_network and cases:
            dossier["cases"][0]["body"] = "network-dossier-private-body"
        self.write_json(handler, 200, dossier)

    def _network_dossier_for_test(self, room_id):
        room = self.network_rooms[room_id]
        cases = []
        for case_id in self.network_room_cases.get(room_id, []):
            case = self.cases[case_id]
            cases.append(
                {
                    "case_id": case["id"],
                    "customer_id": case["customer_id"],
                    "owned_by_requester": True,
                    "status": case["status"],
                    "public_summary": case["public_summary"],
                    "risk_score": case["risk_score"],
                    "typology_hint": case["typology_hint"],
                    "public_risk_tags": ["typology:counterparty-watchlist"],
                    "scope_coverage_complete": True,
                    "created_at": "2026-09-01T00:00:15Z",
                    "updated_at": "2026-09-01T00:00:16Z",
                }
            )
        return {
            "room": dict(room),
            "cases": cases,
            "scope_policy": "case_reference_scope",
            "coverage_policy": "summary_coverage",
        }

    def write_json(self, handler, status, payload):
        self.responses.append({"method": handler.command, "path": handler.path, "status": status, "payload": payload})
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(raw)
        handler.wfile.flush()
        handler.close_connection = True


def stop_fake_server(server, thread):
    try:
        server.shutdown()
    finally:
        server.server_close()
    thread.join(timeout=2)
    if thread.is_alive():
        raise AssertionError(f"{thread.name} did not stop after server shutdown")


@contextlib.contextmanager
def fake_check_service(**kwargs):
    server = FakeCheckServer(**kwargs)
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.05),
        daemon=True,
        name="checker-check-fake-httpd",
    )
    server._serve_thread = thread
    thread.start()
    try:
        yield server
    finally:
        stop_fake_server(server, thread)


class CheckerCheckWorkflowTest(unittest.TestCase):
    def test_check_dispatch_runs_named_subchecks(self):
        calls = []

        def first(client, secret, context):
            calls.append(("first", client.base_url, secret, context.mode, bool(context.run_id)))

        def second(client, secret, context):
            calls.append(("second", client.base_url, secret, context.mode, bool(context.run_id)))

        client = checker_lib.SentinelAMLClient("example.test")
        completed = checker_lib.run_check_subchecks(
            client,
            ["first", "second"],
            SECRET,
            registry={
                "first": checker_lib.CheckSubcheck("first", "first fake", first),
                "second": checker_lib.CheckSubcheck("second", "second fake", second),
            },
        )

        self.assertEqual(completed, ["first", "second"])
        self.assertEqual(calls, [("first", "http://example.test:8081", SECRET, "check", True), ("second", "http://example.test:8081", SECRET, "check", True)])

    def test_unsupported_subcheck_fails_mumble(self):
        client = checker_lib.SentinelAMLClient("example.test")

        with self.assertRaises(checker_lib.CheckFailedError) as caught:
            checker_lib.run_check_subchecks(client, ["missing"], SECRET, registry={})

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)
        self.assertIn("missing: unsupported subcheck", str(caught.exception))

    def test_subcheck_failure_messages_are_independent_and_redacted(self):
        def leaky(_client, _secret, _context):
            raise checker_lib.ServiceMumbleError(
                "token=owner-token password=owner-password FLAG{check-secret} private_state=encoded-state"
            )

        client = checker_lib.SentinelAMLClient("example.test")
        with self.assertRaises(checker_lib.CheckFailedError) as caught:
            checker_lib.run_check_subchecks(
                client,
                ["leaky"],
                SECRET,
                registry={"leaky": checker_lib.CheckSubcheck("leaky", "leaky fake", leaky)},
            )

        message = str(caught.exception)
        for sensitive in ("owner-token", "owner-password", "FLAG{check-secret}", "encoded-state"):
            self.assertNotIn(sensitive, message)
        self.assertIn("leaky:", message)

    def test_default_check_uses_basic_notes_edd_dedup_audit_and_graph_routes(self):
        with fake_check_service() as server:
            completed = checker_lib.run_check(server.url, secret=SECRET, timeout=2.0)

        self.assertEqual(completed, list(checker_lib.DEFAULT_CHECK_SUBCHECKS))
        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertEqual(paths[0], ("GET", "/healthz"))
        self.assertIn(("GET", "/api/customers/1201"), paths)
        self.assertIn(("GET", "/api/customers/1201/accounts"), paths)
        self.assertIn(("GET", "/api/transactions/3201"), paths)
        self.assertIn(("GET", "/api/customers/1201/transactions"), paths)
        self.assertTrue(any(path[0] == "POST" and path[1].startswith("/api/cases/") and path[1].endswith("/notes") for path in paths))
        self.assertTrue(any(path[0] == "GET" and path[1].startswith("/api/cases/") and path[1].endswith("/notes") for path in paths))
        self.assertTrue(any(path[0] == "POST" and path[1].startswith("/api/customers/") and path[1].endswith("/edd") for path in paths))
        self.assertTrue(any(path[0] == "GET" and path[1].startswith("/api/customers/") and path[1].endswith("/edd") for path in paths))
        self.assertTrue(any(path[0] == "GET" and path[1].endswith("/duplicates") for path in paths))
        self.assertTrue(any(path[0] == "GET" and path[1].endswith("/merge-preview") for path in paths))
        self.assertTrue(any(path[0] == "GET" and path[1].startswith("/api/cases/") and path[1].endswith("/timeline") for path in paths))
        self.assertTrue(any(path[0] == "GET" and path[1].startswith("/api/graph/entities/") for path in paths))
        self.assertTrue(any(path[0] == "GET" and path[1].endswith("/related-cases") for path in paths))
        self.assertTrue(any(path[0] == "POST" and path[1].startswith("/api/cases/") and path[1].endswith("/exports") for path in paths))
        self.assertTrue(any(path[0] == "GET" and path[1].startswith("/api/exports/") for path in paths))
        self.assertIn(("GET", "/api/network/rooms"), paths)
        self.assertTrue(any(path[0] == "GET" and path[1].startswith("/api/network/rooms/") and path[1].endswith("/dossier") for path in paths))

    def test_basic_notes_and_dedup_check_route_order(self):
        with fake_check_service() as server:
            completed = checker_lib.run_check(
                server.url,
                subchecks=("check_basic", "check_case_notes", "check_dedup"),
                secret=SECRET,
                timeout=2.0,
            )

        self.assertEqual(completed, ["check_basic", "check_case_notes", "check_dedup"])
        paths = [(request["method"], request["path"]) for request in server.requests]
        expected_order = [
            ("POST", "/api/auth/register"),
            ("POST", "/api/customers"),
            ("GET", "/api/customers/1201"),
            ("POST", "/api/customers/1201/accounts"),
            ("GET", "/api/customers/1201/accounts"),
            ("POST", "/api/transactions"),
            ("GET", "/api/transactions/3201"),
            ("GET", "/api/customers/1201/transactions"),
            ("POST", "/api/cases/5201/notes"),
            ("GET", "/api/cases/5201/notes"),
            ("GET", "/api/cases/5202/duplicates"),
            ("GET", "/api/cases/5202/duplicates/5203/merge-preview"),
        ]
        cursor = 0
        for expected in expected_order:
            try:
                cursor = paths.index(expected, cursor) + 1
            except ValueError as exc:
                raise AssertionError(f"missing route in expected order: {expected}") from exc

    def test_checker_cli_check_outputs_ok_and_uses_dispatcher(self):
        previous_secret = os.environ.get(checker_lib.CHECKER_SECRET_ENV)
        os.environ[checker_lib.CHECKER_SECRET_ENV] = SECRET
        stdout = io.StringIO()
        stderr = io.StringIO()
        with fake_check_service() as server:
            try:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = checker.main(["checker.py", "check", server.url])
            finally:
                if previous_secret is None:
                    os.environ.pop(checker_lib.CHECKER_SECRET_ENV, None)
                else:
                    os.environ[checker_lib.CHECKER_SECRET_ENV] = previous_secret

        self.assertEqual(exit_code, checker_lib.EXIT_OK, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "OK")
        self.assertEqual(stderr.getvalue().strip(), "OK")
        self.assertGreaterEqual(len(server.requests), 4)

    def test_havoc_cli_uses_same_safe_framework(self):
        previous_secret = os.environ.get(checker_lib.CHECKER_SECRET_ENV)
        os.environ[checker_lib.CHECKER_SECRET_ENV] = SECRET
        stdout = io.StringIO()
        stderr = io.StringIO()
        with fake_check_service() as server:
            try:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = checker.main(["checker.py", "havoc", server.url])
            finally:
                if previous_secret is None:
                    os.environ.pop(checker_lib.CHECKER_SECRET_ENV, None)
                else:
                    os.environ[checker_lib.CHECKER_SECRET_ENV] = previous_secret

        self.assertEqual(exit_code, checker_lib.EXIT_OK, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "OK")
        self.assertEqual(stderr.getvalue().strip(), "OK")
        self.assertGreaterEqual(len(server.requests), 4)

    def test_check_cli_errors_do_not_print_sensitive_strings(self):
        secret_flag = "FLAG{do-not-print}"

        def failing_run_check(_host):
            raise checker_lib.ServiceMumbleError(
                f"subcheck failed token=owner-token password=owner-password {secret_flag} private_state=encoded-state"
            )

        original = checker.run_check
        checker.run_check = failing_run_check
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stderr(stderr):
                exit_code = checker.main(["checker.py", "check", "127.0.0.1"])
        finally:
            checker.run_check = original

        self.assertEqual(exit_code, checker_lib.EXIT_MUMBLE)
        output = stderr.getvalue()
        for sensitive in ("owner-token", "owner-password", secret_flag, "encoded-state"):
            self.assertNotIn(sensitive, output)

    def test_checker_secret_fails_closed_when_env_missing_empty_or_legacy_default(self):
        previous_secret = os.environ.get(checker_lib.CHECKER_SECRET_ENV)
        try:
            for value in (None, "", "sentinel_aml_checker_wave11_dev_secret"):
                with self.subTest(value=value):
                    if value is None:
                        os.environ.pop(checker_lib.CHECKER_SECRET_ENV, None)
                    else:
                        os.environ[checker_lib.CHECKER_SECRET_ENV] = value
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        exit_code = checker.main(["checker.py", "check", "127.0.0.1"])
                    self.assertEqual(exit_code, checker_lib.EXIT_CHECKER_ERROR)
                    self.assertIn("checker secret is not configured", stdout.getvalue())
                    self.assertIn("checker secret is not configured", stderr.getvalue())
        finally:
            if previous_secret is None:
                os.environ.pop(checker_lib.CHECKER_SECRET_ENV, None)
            else:
                os.environ[checker_lib.CHECKER_SECRET_ENV] = previous_secret

    def test_repeated_check_and_havoc_use_fresh_context_ids(self):
        contexts: list[checker_lib.CheckRunContext] = []

        def record_context(_client, _secret, context):
            contexts.append(context)

        registry = {"health": checker_lib.CheckSubcheck("health", "record context", record_context)}
        with fake_check_service() as server:
            client = checker_lib.SentinelAMLClient(server.url, timeout=2.0)
            checker_lib.run_check_subchecks(
                client,
                ("health",),
                SECRET,
                context=checker_lib.new_check_run_context("check"),
                registry=registry,
            )
            checker_lib.run_check_subchecks(
                client,
                ("health",),
                SECRET,
                context=checker_lib.new_check_run_context("check"),
                registry=registry,
            )
            checker_lib.run_check_subchecks(
                client,
                ("health",),
                SECRET,
                context=checker_lib.new_check_run_context("havoc"),
                registry=registry,
            )
            checker_lib.run_check_subchecks(
                client,
                ("health",),
                SECRET,
                context=checker_lib.new_check_run_context("havoc"),
                registry=registry,
            )

        self.assertEqual([context.mode for context in contexts], ["check", "check", "havoc", "havoc"])
        self.assertEqual(len({context.run_id for context in contexts}), 4)

    def test_check_failed_subcheck_returns_non_ok(self):
        with fake_check_service(fail_route="/api/customers", fail_status=500, fail_body={"error": "FLAG{hidden}"}) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)
        self.assertNotIn("FLAG{hidden}", str(caught.exception))

    def test_check_dedup_fails_when_candidate_is_missing(self):
        with fake_check_service(omit_dedup_candidate=True) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, subchecks=("check_dedup",), secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)
        self.assertIn("check_dedup:", str(caught.exception))

    def test_check_dedup_rejects_private_fields_in_merge_preview(self):
        with fake_check_service(leak_private_merge_preview=True) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, subchecks=("check_dedup",), secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)
        self.assertNotIn("foreign-private-body", str(caught.exception))

    def test_check_case_notes_missing_note_api_fails_closed(self):
        with fake_check_service(fail_route="/api/cases/5201/notes", fail_status=404) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, subchecks=("check_case_notes",), secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)
        self.assertIn("check_case_notes:", str(caught.exception))

    def test_check_case_notes_does_not_read_foreign_case_body(self):
        with fake_check_service() as server:
            checker_lib.run_check(server.url, subchecks=("check_case_notes",), secret=SECRET, timeout=2.0)

        paths = [request["path"] for request in server.requests]
        note_paths = [path for path in paths if path.startswith("/api/cases/") and path.endswith("/notes")]
        self.assertEqual(len(note_paths), 2)
        self.assertEqual(len({path.rsplit("/", 1)[0] for path in note_paths}), 1)
        for request in server.requests:
            if request["body"]:
                serialized = json.dumps(request["body"], sort_keys=True)
                self.assertNotIn("FLAG{", serialized)

    def test_check_audit_timeline_has_event_but_no_raw_private_body(self):
        with fake_check_service() as server:
            checker_lib.run_check(server.url, subchecks=("check_audit",), secret=SECRET, timeout=2.0)

        timeline_requests = [request for request in server.requests if request["path"].endswith("/timeline")]
        self.assertEqual(len(timeline_requests), 1)
        note_bodies = [
            request["body"]["body"]
            for request in server.requests
            if request["path"].endswith("/notes") and request["method"] == "POST"
        ]
        self.assertEqual(len(note_bodies), 1)
        timeline_payload = {"events": server._timeline_events_for_test()}
        self.assertNotIn(note_bodies[0], json.dumps(timeline_payload, sort_keys=True))

    def test_check_audit_rejects_raw_private_body_in_timeline(self):
        with fake_check_service(leak_private_timeline=True) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, subchecks=("check_audit",), secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)
        self.assertNotIn("checker check nonsecret note", str(caught.exception))

    def test_check_audit_missing_module_fails_closed(self):
        with fake_check_service(audit_available=False) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, subchecks=("check_audit",), secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)
        self.assertTrue(any(request["path"].endswith("/timeline") for request in server.requests))

    def test_check_audit_missing_note_event_fails_closed(self):
        with fake_check_service(omit_timeline_note_event=True) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, subchecks=("check_audit",), secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)

    def test_check_edd_creates_and_reads_owner_confidential_comment(self):
        with fake_check_service() as server:
            checker_lib.run_check(server.url, subchecks=("check_edd",), secret=SECRET, timeout=2.0)

        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertTrue(any(path[0] == "POST" and path[1].startswith("/api/customers/") and path[1].endswith("/edd") for path in paths))
        self.assertTrue(any(path[0] == "GET" and path[1].startswith("/api/customers/") and path[1].endswith("/edd") for path in paths))
        edd_writes = [
            request
            for request in server.requests
            if request["method"] == "POST" and request["path"].startswith("/api/customers/") and request["path"].endswith("/edd")
        ]
        self.assertEqual(len(edd_writes), 1)
        self.assertIn("confidential_comment", edd_writes[0]["body"])
        self.assertNotIn("FLAG{", json.dumps(edd_writes[0]["body"], sort_keys=True))

    def test_check_edd_missing_owner_view_fails_closed(self):
        with fake_check_service(fail_route="/api/customers/1201/edd", fail_status=404) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, subchecks=("check_edd",), secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)
        self.assertIn("check_edd:", str(caught.exception))

    def test_check_graph_returns_public_metadata_only(self):
        with fake_check_service() as server:
            checker_lib.run_check(server.url, subchecks=("check_graph",), secret=SECRET, timeout=2.0)

        graph_paths = [request["path"] for request in server.requests if request["path"].startswith("/api/graph/entities/")]
        self.assertEqual(len(graph_paths), 2)
        self.assertTrue(any(path.endswith("/related-cases") for path in graph_paths))
        self.assertFalse(any("edd-summaries" in path for path in graph_paths))
        graph_responses = [
            response["payload"]
            for response in server.responses
            if response["path"].startswith("/api/graph/entities/") and response["status"] == 200
        ]
        self.assertEqual(graph_responses[0]["relation_type"], "shared_entity_hint")
        self.assertGreaterEqual(graph_responses[0]["customer_count"], 2)
        self.assertGreaterEqual(graph_responses[0]["case_count"], 2)
        related_cases = graph_responses[1]["cases"]
        self.assertGreaterEqual(len(related_cases), 2)
        serialized = json.dumps(graph_responses, sort_keys=True)
        for private_marker in ("confidential_comment", "private-body", "private_notes", "body", "source_of_funds", "risk_rationale"):
            self.assertNotIn(private_marker, serialized)

    def test_check_graph_rejects_private_fields(self):
        with fake_check_service(leak_private_graph=True) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, subchecks=("check_graph",), secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)

    def test_check_graph_missing_module_fails_closed(self):
        with fake_check_service(graph_available=False) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, subchecks=("check_graph",), secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)
        self.assertTrue(any(request["path"].startswith("/api/graph/entities/") for request in server.requests))

    def test_check_export_creates_and_retrieves_redacted_bundle(self):
        with fake_check_service() as server:
            checker_lib.run_check(server.url, subchecks=("check_export",), secret=SECRET, timeout=2.0)

        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertTrue(any(path[0] == "POST" and path[1].startswith("/api/cases/") and path[1].endswith("/exports") for path in paths))
        self.assertTrue(any(path[0] == "GET" and path[1].startswith("/api/exports/") for path in paths))
        note_body = next(
            request["body"]["body"]
            for request in server.requests
            if request["method"] == "POST" and request["path"].endswith("/notes")
        )
        export_json = json.dumps(server.exports, sort_keys=True)
        self.assertNotIn(note_body, export_json)
        self.assertIn("public_redacted", export_json)

    def test_check_export_disabled_fails_closed(self):
        with fake_check_service(export_available=False) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, subchecks=("check_export",), secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)
        self.assertTrue(any(request["path"].endswith("/exports") for request in server.requests))

    def test_check_export_rejects_private_fields(self):
        with fake_check_service(leak_private_export=True) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, subchecks=("check_export",), secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)

    def test_check_network_room_summary_and_dossier_public_shape(self):
        with fake_check_service() as server:
            checker_lib.run_check(server.url, subchecks=("check_network_room",), secret=SECRET, timeout=2.0)

        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertIn(("GET", "/api/network/rooms"), paths)
        self.assertTrue(any(path[0] == "GET" and path[1].startswith("/api/network/rooms/") and path[1].endswith("/dossier") for path in paths))
        dossier_path = next(path for method, path in paths if method == "GET" and path.endswith("/dossier"))
        room_id = int(dossier_path.strip("/").split("/")[3])
        dossier = server._network_dossier_for_test(room_id)
        self.assertEqual(dossier["scope_policy"], "case_reference_scope")
        self.assertEqual(dossier["coverage_policy"], "summary_coverage")
        self.assertGreaterEqual(len(dossier["cases"]), 2)
        self.assertTrue(all(case["scope_coverage_complete"] is True for case in dossier["cases"]))
        serialized = json.dumps(dossier, sort_keys=True)
        self.assertNotIn("body", serialized)
        self.assertNotIn("confidential_comment", serialized)

    def test_check_network_room_waits_for_worker_materialization(self):
        original_wait = checker_lib.NETWORK_ROOM_WAIT_SECONDS
        original_poll = checker_lib.NETWORK_ROOM_POLL_SECONDS
        checker_lib.NETWORK_ROOM_WAIT_SECONDS = 1.0
        checker_lib.NETWORK_ROOM_POLL_SECONDS = 0.01
        try:
            with fake_check_service(network_room_list_delay=2) as server:
                checker_lib.run_check(server.url, subchecks=("check_network_room",), secret=SECRET, timeout=2.0)
        finally:
            checker_lib.NETWORK_ROOM_WAIT_SECONDS = original_wait
            checker_lib.NETWORK_ROOM_POLL_SECONDS = original_poll

        room_list_requests = [
            request for request in server.requests if (request["method"], request["path"]) == ("GET", "/api/network/rooms")
        ]
        self.assertGreaterEqual(len(room_list_requests), 3)

    def test_check_network_room_disabled_fails_closed(self):
        with fake_check_service(network_available=False) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, subchecks=("check_network_room",), secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)
        self.assertIn(("GET", "/api/network/rooms"), [(request["method"], request["path"]) for request in server.requests])

    def test_check_network_room_missing_materialized_room_fails_closed(self):
        original_wait = checker_lib.NETWORK_ROOM_WAIT_SECONDS
        original_poll = checker_lib.NETWORK_ROOM_POLL_SECONDS
        checker_lib.NETWORK_ROOM_WAIT_SECONDS = 0.05
        checker_lib.NETWORK_ROOM_POLL_SECONDS = 0.01
        try:
            with fake_check_service(omit_network_room=True) as server:
                with self.assertRaises(checker_lib.CheckFailedError) as caught:
                    checker_lib.run_check(server.url, subchecks=("check_network_room",), secret=SECRET, timeout=2.0)
        finally:
            checker_lib.NETWORK_ROOM_WAIT_SECONDS = original_wait
            checker_lib.NETWORK_ROOM_POLL_SECONDS = original_poll

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)
        self.assertIn("after bounded wait", str(caught.exception))
        self.assertIn(("GET", "/api/network/rooms"), [(request["method"], request["path"]) for request in server.requests])

    def test_check_network_room_rejects_private_fields(self):
        with fake_check_service(leak_private_network=True) as server:
            with self.assertRaises(checker_lib.CheckFailedError) as caught:
                checker_lib.run_check(server.url, subchecks=("check_network_room",), secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.exit_code, checker_lib.EXIT_MUMBLE)

    def test_putnoise_public_data_contains_no_credentials_or_flags(self):
        with fake_check_service() as server:
            result = checker_lib.put_noise(server.url, seed="FLAG{noise-seed}", secret=SECRET, timeout=2.0)

        public = result.public_attack_data
        checker_lib.assert_noise_public_data_safe(public)
        serialized = json.dumps(public, sort_keys=True).lower()
        state = checker_lib.decode_noise_state(result.private_state, SECRET)
        for forbidden in ("flag{noise-seed}", state.username.lower(), state.password.lower(), state.token.lower(), "private_state"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(public["service"], checker_lib.SERVICE_NAME)
        self.assertEqual(public["kind"], "noise")

    def test_noise_does_not_write_flags_to_checker_flag_stores(self):
        with fake_check_service() as server:
            checker_lib.put_noise(server.url, seed="round-13", secret=SECRET, timeout=2.0)

        flag_store_writes = [
            request
            for request in server.requests
            if request["method"] == "POST" and (request["path"].endswith("/notes") or request["path"].endswith("/edd"))
        ]
        self.assertEqual(len(flag_store_writes), 2)
        for request in flag_store_writes:
            serialized = json.dumps(request["body"], sort_keys=True)
            self.assertNotIn("FLAG{", serialized)

    def test_getnoise_verifies_encoded_noise_state(self):
        with fake_check_service() as server:
            result = checker_lib.put_noise(server.url, seed="round-13", secret=SECRET, timeout=2.0)
            server.requests.clear()
            checker_lib.get_noise(server.url, result.private_state, secret=SECRET, timeout=2.0)

        paths = [(request["method"], request["path"]) for request in server.requests]
        state = checker_lib.decode_noise_state(result.private_state, SECRET)
        self.assertIn(("GET", f"/api/customers/{state.customer_ids[0]}"), paths)
        self.assertIn(("GET", f"/api/customers/{state.customer_ids[1]}"), paths)
        self.assertIn(("GET", f"/api/exports/{state.export_id}"), paths)
        self.assertTrue(any(path[0] == "GET" and path[1].endswith("/dossier") for path in paths))

    def test_putnoise_cli_outputs_noise_shape(self):
        previous_secret = os.environ.get(checker_lib.CHECKER_SECRET_ENV)
        os.environ[checker_lib.CHECKER_SECRET_ENV] = SECRET
        stdout = io.StringIO()
        stderr = io.StringIO()
        with fake_check_service() as server:
            try:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = checker.main(["checker.py", "putnoise", server.url, "round-13"])
            finally:
                if previous_secret is None:
                    os.environ.pop(checker_lib.CHECKER_SECRET_ENV, None)
                else:
                    os.environ[checker_lib.CHECKER_SECRET_ENV] = previous_secret

        self.assertEqual(exit_code, checker_lib.EXIT_OK, stderr.getvalue())
        public = json.loads(stdout.getvalue())
        private = stderr.getvalue().strip()
        checker_lib.decode_noise_state(private, SECRET)
        checker_lib.assert_noise_public_data_safe(public)
        self.assertEqual(public["service"], checker_lib.SERVICE_NAME)
        self.assertEqual(public["kind"], "noise")


if __name__ == "__main__":
    unittest.main()
