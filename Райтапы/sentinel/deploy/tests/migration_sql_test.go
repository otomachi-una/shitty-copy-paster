package tests

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestMigrationsExistAndAreOrdered(t *testing.T) {
	root := repositoryRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "migrations"))
	if err != nil {
		t.Fatalf("read migrations directory: %v", err)
	}

	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}

	expected := []string{
		"000001_create_users_sessions.sql",
		"000002_create_customers_accounts_transactions.sql",
		"000003_create_alerts_cases_notes.sql",
		"000004_create_edd_records.sql",
		"000005_add_case_dedup_hint.sql",
		"000006_create_audit_events.sql",
		"000007_create_entity_graph.sql",
		"000008_create_exports_disputes.sql",
		"000009_create_network_rooms.sql",
		"000010_create_network_room_artifacts.sql",
		"000011_network_room_dirty_candidates.sql",
	}
	if strings.Join(names, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected migration order/name: %v", names)
	}
}

func TestInitialMigrationDefinesUsersAndSessions(t *testing.T) {
	sql := readMigration(t, "000001_create_users_sessions.sql")
	requiredSnippets := []string{
		"CREATE TABLE users",
		"id bigserial PRIMARY KEY",
		"username text NOT NULL",
		"password_hash text NOT NULL",
		"role text NOT NULL",
		"status text NOT NULL DEFAULT 'active'",
		"created_at timestamptz NOT NULL DEFAULT now()",
		"UNIQUE (username)",
		"CHECK (role IN ('analyst', 'senior_analyst', 'supervisor', 'auditor', 'system_worker'))",
		"CHECK (status IN ('active', 'disabled'))",
		"CREATE TABLE sessions",
		"user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"token_hash text NOT NULL",
		"expires_at timestamptz NOT NULL",
		"revoked_at timestamptz",
		"UNIQUE (token_hash)",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(sql, snippet) {
			t.Fatalf("migration missing required snippet %q", snippet)
		}
	}
}

func TestInitialMigrationDoesNotStoreRawTokensOrFlags(t *testing.T) {
	sql := strings.ToLower(readMigration(t, "000001_create_users_sessions.sql"))
	forbidden := []string{
		" token ",
		"raw_token",
		"plain_token",
		"flag" + "_value",
		"secret" + "_for_checker",
		"case_notes",
		"edd_records",
		"customers",
		"accounts",
		"transactions",
		"alerts",
	}

	for _, value := range forbidden {
		if strings.Contains(sql, value) {
			t.Fatalf("migration contains out-of-scope or sensitive marker %q", value)
		}
	}

	if regexp.MustCompile(`\btoken_hash\b`).FindAllString(sql, -1) == nil {
		t.Fatal("migration must store token_hash")
	}
}

func TestWave03MigrationDefinesCustomersAccountsAndTransactions(t *testing.T) {
	sql := readMigration(t, "000002_create_customers_accounts_transactions.sql")
	requiredSnippets := []string{
		"CREATE TABLE customers",
		"owner_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"display_name text NOT NULL",
		"customer_type text NOT NULL",
		"country text NOT NULL",
		"registration_number text NOT NULL",
		"risk_level text NOT NULL DEFAULT 'medium'",
		"entity_hint text NOT NULL DEFAULT ''",
		"status text NOT NULL DEFAULT 'active'",
		"UNIQUE (owner_user_id, registration_number)",
		"CHECK (customer_type IN ('individual', 'organization'))",
		"CHECK (risk_level IN ('low', 'medium', 'high'))",
		"CREATE INDEX customers_owner_user_id_idx",
		"CREATE TABLE accounts",
		"customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE",
		"iban_like text NOT NULL",
		"currency text NOT NULL",
		"UNIQUE (customer_id, iban_like)",
		"CREATE INDEX accounts_customer_id_idx",
		"CREATE TABLE transactions",
		"account_id bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE",
		"counterparty_name text NOT NULL",
		"counterparty_country text NOT NULL",
		"counterparty_fingerprint text NOT NULL",
		"amount numeric(18,2) NOT NULL",
		"direction text NOT NULL",
		"purpose text NOT NULL",
		"trace_id text NOT NULL",
		"risk_score integer NOT NULL DEFAULT 0",
		"CHECK (direction IN ('inbound', 'outbound'))",
		"CHECK (risk_score >= 0 AND risk_score <= 100)",
		"CREATE INDEX transactions_account_id_idx",
		"CREATE INDEX transactions_counterparty_fingerprint_idx",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(sql, snippet) {
			t.Fatalf("Wave 03 migration missing required snippet %q", snippet)
		}
	}
}

func TestWave04MigrationDefinesAlertsCasesAndCaseNotes(t *testing.T) {
	sql := readMigration(t, "000003_create_alerts_cases_notes.sql")
	requiredSnippets := []string{
		"CREATE TABLE alerts",
		"transaction_id bigint NOT NULL REFERENCES transactions(id) ON DELETE CASCADE",
		"customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE",
		"rule_code text NOT NULL",
		"risk_score integer NOT NULL DEFAULT 0",
		"status text NOT NULL DEFAULT 'NEW'",
		"assigned_user_id bigint REFERENCES users(id) ON DELETE SET NULL",
		"typology_hint text NOT NULL DEFAULT ''",
		"UNIQUE (transaction_id, rule_code)",
		"CHECK (status IN ('NEW', 'TRIAGED', 'CASE_OPENED', 'ESCALATED', 'CLOSED'))",
		"CREATE INDEX alerts_transaction_id_idx",
		"CREATE INDEX alerts_customer_status_idx",
		"CREATE TABLE cases",
		"alert_id bigint NOT NULL REFERENCES alerts(id) ON DELETE RESTRICT",
		"owner_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"status text NOT NULL DEFAULT 'OPEN'",
		"public_summary text NOT NULL DEFAULT ''",
		"UNIQUE (alert_id)",
		"CHECK (status IN ('OPEN', 'UNDER_REVIEW', 'ESCALATED', 'REPORTED', 'CLOSED'))",
		"CREATE INDEX cases_owner_status_idx",
		"CREATE TABLE case_notes",
		"case_id bigint NOT NULL REFERENCES cases(id) ON DELETE CASCADE",
		"author_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT",
		"visibility text NOT NULL DEFAULT 'private'",
		"body text NOT NULL",
		"CHECK (visibility IN ('private', 'internal'))",
		"CREATE INDEX case_notes_case_id_idx",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(sql, snippet) {
			t.Fatalf("Wave 04 migration missing required snippet %q", snippet)
		}
	}
}

func TestWave05MigrationDefinesEDDRecords(t *testing.T) {
	sql := readMigration(t, "000004_create_edd_records.sql")
	requiredSnippets := []string{
		"CREATE TABLE edd_records",
		"customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE RESTRICT",
		"analyst_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT",
		"source_of_funds text NOT NULL",
		"risk_rationale text NOT NULL",
		"confidential_comment text NOT NULL",
		"review_status text NOT NULL DEFAULT 'DRAFT'",
		"UNIQUE (customer_id)",
		"CHECK (review_status IN ('DRAFT', 'IN_REVIEW', 'APPROVED', 'REJECTED'))",
		"CREATE INDEX edd_records_customer_id_idx",
		"CREATE INDEX edd_records_analyst_user_id_idx",
		"CREATE INDEX edd_records_review_status_idx",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(sql, snippet) {
			t.Fatalf("Wave 05 migration missing required snippet %q", snippet)
		}
	}
}

func TestWave07MigrationAddsCaseDedupHint(t *testing.T) {
	sql := readMigration(t, "000005_add_case_dedup_hint.sql")
	requiredSnippets := []string{
		"ALTER TABLE cases",
		"ADD COLUMN dedup_hint text NOT NULL DEFAULT ''",
		"ADD CONSTRAINT cases_dedup_hint_not_blank_when_set",
		"CHECK (dedup_hint = '' OR btrim(dedup_hint) <> '')",
		"CREATE INDEX cases_dedup_hint_idx ON cases(dedup_hint) WHERE dedup_hint <> ''",
		"CREATE INDEX cases_owner_dedup_hint_idx ON cases(owner_user_id, dedup_hint) WHERE dedup_hint <> ''",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(sql, snippet) {
			t.Fatalf("Wave 07 migration missing required snippet %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"CREATE TABLE dedup",
		"case_notes",
		"edd_records",
		"confidential_comment",
		"body",
		"flag" + "_value",
		"secret" + "_for_checker",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("Wave 07 dedup migration contains forbidden marker %q", forbidden)
		}
	}
}

func TestWave08MigrationDefinesAuditEvents(t *testing.T) {
	sql := readMigration(t, "000006_create_audit_events.sql")
	requiredSnippets := []string{
		"CREATE TABLE audit_events",
		"id bigserial PRIMARY KEY",
		"actor_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT",
		"object_type text NOT NULL",
		"object_id bigint NOT NULL",
		"event_type text NOT NULL",
		"public_message text NOT NULL DEFAULT ''",
		"diff_json jsonb NOT NULL DEFAULT '[]'::jsonb",
		"created_at timestamptz NOT NULL DEFAULT now()",
		"visibility_scope text NOT NULL DEFAULT 'owner'",
		"CHECK (object_id > 0)",
		"CHECK (object_type IN ('customer', 'account', 'transaction', 'alert', 'case', 'case_note', 'edd_record'))",
		"CHECK (event_type IN ('created', 'updated', 'status_changed', 'claimed', 'triaged', 'reviewed'))",
		"CHECK (visibility_scope IN ('owner', 'internal', 'system'))",
		"CHECK (jsonb_typeof(diff_json) = 'array')",
		"CREATE INDEX audit_events_actor_user_id_idx",
		"CREATE INDEX audit_events_object_idx ON audit_events(object_type, object_id)",
		"CREATE INDEX audit_events_event_type_idx",
		"CREATE INDEX audit_events_visibility_created_idx",
		"CREATE INDEX audit_events_created_at_idx",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(sql, snippet) {
			t.Fatalf("Wave 08 migration missing required snippet %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"confidential_comment",
		"case_note_body",
		"flag" + "_value",
		"secret" + "_for_checker",
		"CREATE TABLE graph",
		"CREATE TABLE exports",
		"CREATE TABLE network",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("Wave 08 audit migration contains forbidden marker %q", forbidden)
		}
	}
}

func TestWave10MigrationsDoNotIntroduceOutOfScopeTablesOrSensitiveFields(t *testing.T) {
	sql := strings.ToLower(readAllMigrations(t))
	forbidden := []string{
		"create table worker_jobs",
		"create table risk_jobs",
		"create table queues",
		"create table dedup",
		"flag" + "_value",
		"secret" + "_for_checker",
	}

	for _, value := range forbidden {
		if strings.Contains(sql, value) {
			t.Fatalf("migrations contain out-of-scope or sensitive marker %q", value)
		}
	}
}

func TestWave09MigrationDefinesEntityGraph(t *testing.T) {
	sql := readMigration(t, "000007_create_entity_graph.sql")
	requiredSnippets := []string{
		"CREATE TABLE entity_graph_nodes",
		"id bigserial PRIMARY KEY",
		"entity_hint text NOT NULL",
		"node_type text NOT NULL",
		"display_label text NOT NULL DEFAULT ''",
		"public_risk_tags text[] NOT NULL DEFAULT '{}'::text[]",
		"UNIQUE (entity_hint, node_type)",
		"CHECK (btrim(entity_hint) <> '')",
		"CHECK (node_type IN ('customer_entity', 'counterparty', 'case_cluster', 'edd_status'))",
		"CREATE TABLE entity_graph_edges",
		"source_node_id bigint NOT NULL REFERENCES entity_graph_nodes(id) ON DELETE CASCADE",
		"target_node_id bigint NOT NULL REFERENCES entity_graph_nodes(id) ON DELETE CASCADE",
		"relation_type text NOT NULL",
		"strength integer NOT NULL DEFAULT 0",
		"public_summary text NOT NULL DEFAULT ''",
		"UNIQUE (source_node_id, target_node_id, relation_type)",
		"CHECK (source_node_id <> target_node_id)",
		"CHECK (relation_type IN ('shared_entity_hint', 'shared_counterparty', 'same_case_cluster', 'edd_status_overlap'))",
		"CHECK (strength >= 0 AND strength <= 100)",
		"CREATE INDEX entity_graph_nodes_entity_hint_idx",
		"CREATE INDEX entity_graph_nodes_node_type_idx",
		"CREATE INDEX entity_graph_edges_source_node_id_idx",
		"CREATE INDEX entity_graph_edges_target_node_id_idx",
		"CREATE INDEX entity_graph_edges_relation_type_idx",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(sql, snippet) {
			t.Fatalf("Wave 09 graph migration missing required snippet %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"case_notes",
		"body",
		"edd_records",
		"confidential_comment",
		"source_of_funds",
		"risk_rationale",
		"diff_json",
		"password_hash",
		"token_hash",
		"flag" + "_value",
		"secret" + "_for_checker",
	} {
		if strings.Contains(strings.ToLower(sql), forbidden) {
			t.Fatalf("Wave 09 graph migration contains forbidden marker %q", forbidden)
		}
	}
}

func TestWave10MigrationDefinesExportsAndDisputes(t *testing.T) {
	sql := readMigration(t, "000008_create_exports_disputes.sql")
	requiredSnippets := []string{
		"CREATE TABLE disputes",
		"owner_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"case_id bigint NOT NULL REFERENCES cases(id) ON DELETE RESTRICT",
		"status text NOT NULL DEFAULT 'OPEN'",
		"reason text NOT NULL",
		"resolution_summary text NOT NULL DEFAULT ''",
		"UNIQUE (owner_user_id, case_id, status)",
		"CHECK (status IN ('OPEN', 'UNDER_REVIEW', 'RESOLVED', 'REJECTED'))",
		"CREATE INDEX disputes_owner_status_idx",
		"CREATE INDEX disputes_case_id_idx",
		"CREATE TABLE exports",
		"root_case_id bigint NOT NULL REFERENCES cases(id) ON DELETE RESTRICT",
		"dispute_id bigint REFERENCES disputes(id) ON DELETE SET NULL",
		"purpose text NOT NULL",
		"status text NOT NULL DEFAULT 'PENDING'",
		"bundle_json jsonb NOT NULL DEFAULT '{}'::jsonb",
		"redaction_policy text NOT NULL DEFAULT 'public_redacted'",
		"expires_at timestamptz NOT NULL DEFAULT (now() + interval '7 days')",
		"CHECK (status IN ('PENDING', 'GENERATED', 'FAILED', 'EXPIRED'))",
		"CHECK (redaction_policy IN ('public_redacted'))",
		"CREATE INDEX exports_owner_status_idx",
		"CREATE INDEX exports_root_case_id_idx",
		"CREATE TABLE export_items",
		"export_id bigint NOT NULL REFERENCES exports(id) ON DELETE CASCADE",
		"item_type text NOT NULL",
		"object_type text NOT NULL",
		"object_id bigint NOT NULL",
		"relation text NOT NULL",
		"payload_json jsonb NOT NULL DEFAULT '{}'::jsonb",
		"UNIQUE (export_id, item_type, object_type, object_id, relation)",
		"CHECK (item_type IN ('root_case', 'linked_case', 'audit_summary', 'edd_summary', 'metadata'))",
		"CHECK (object_type IN ('case', 'audit_event', 'edd_record', 'export'))",
		"CHECK (relation IN ('root', 'linked', 'audit', 'edd', 'metadata'))",
		"CREATE INDEX export_items_export_id_idx",
		"CREATE INDEX export_items_object_idx",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(sql, snippet) {
			t.Fatalf("Wave 10 export migration missing required snippet %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"case_note_body",
		"confidential_comment",
		"source_of_funds",
		"risk_rationale",
		"old_hash",
		"new_hash",
		"value_hash",
		"password_hash",
		"token_hash",
		"flag" + "_value",
		"secret" + "_for_checker",
		"network_rooms",
	} {
		if strings.Contains(strings.ToLower(sql), forbidden) {
			t.Fatalf("Wave 10 export migration contains forbidden marker %q", forbidden)
		}
	}
}

func TestWave10MigrationDefinesNetworkRooms(t *testing.T) {
	sql := readMigration(t, "000009_create_network_rooms.sql")
	requiredSnippets := []string{
		"CREATE TABLE network_rooms",
		"id bigserial PRIMARY KEY",
		"room_key text NOT NULL",
		"entity_hint text NOT NULL",
		"typology_hint text NOT NULL DEFAULT ''",
		"status text NOT NULL DEFAULT 'OPEN'",
		"public_summary text NOT NULL DEFAULT ''",
		"public_risk_tags text[] NOT NULL DEFAULT '{}'::text[]",
		"created_by_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT",
		"UNIQUE (room_key)",
		"CHECK (status IN ('OPEN', 'MONITORING', 'CLOSED'))",
		"CREATE INDEX network_rooms_entity_hint_idx",
		"CREATE INDEX network_rooms_typology_hint_idx",
		"CREATE INDEX network_rooms_status_idx",
		"CREATE TABLE network_room_cases",
		"room_id bigint NOT NULL REFERENCES network_rooms(id) ON DELETE CASCADE",
		"case_id bigint NOT NULL REFERENCES cases(id) ON DELETE CASCADE",
		"relation_type text NOT NULL DEFAULT 'related_case'",
		"added_by_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT",
		"UNIQUE (room_id, case_id)",
		"CHECK (relation_type IN ('root_case', 'related_case', 'typology_match', 'entity_match'))",
		"CREATE INDEX network_room_cases_room_id_idx",
		"CREATE INDEX network_room_cases_case_id_idx",
		"CREATE TABLE network_room_participants",
		"room_id bigint NOT NULL REFERENCES network_rooms(id) ON DELETE CASCADE",
		"user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"participant_role text NOT NULL DEFAULT 'analyst'",
		"UNIQUE (room_id, user_id)",
		"CHECK (participant_role IN ('analyst', 'observer'))",
		"CREATE INDEX network_room_participants_room_id_idx",
		"CREATE INDEX network_room_participants_user_id_idx",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(sql, snippet) {
			t.Fatalf("Wave 10 network-room migration missing required snippet %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"case_note_body",
		"confidential_comment",
		"source_of_funds",
		"risk_rationale",
		"diff_json",
		"old_hash",
		"new_hash",
		"value_hash",
		"password_hash",
		"token_hash",
		"case_blob",
		"raw_case",
		"flag" + "_value",
		"secret" + "_for_checker",
	} {
		if strings.Contains(strings.ToLower(sql), forbidden) {
			t.Fatalf("Wave 10 network-room migration contains forbidden marker %q", forbidden)
		}
	}
}

func TestNetworkRoomArtifactMigrationDefinesMaterializedCollaborationContext(t *testing.T) {
	sql := readMigration(t, "000010_create_network_room_artifacts.sql")
	requiredSnippets := []string{
		"CREATE TABLE network_room_artifacts",
		"room_id bigint NOT NULL REFERENCES network_rooms(id) ON DELETE CASCADE",
		"case_id bigint NOT NULL REFERENCES cases(id) ON DELETE CASCADE",
		"customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE",
		"artifact_kind text NOT NULL",
		"source_class text NOT NULL",
		"coverage_policy text NOT NULL",
		"content text NOT NULL DEFAULT ''",
		"UNIQUE (room_id, case_id, artifact_kind, source_class)",
		"CHECK (artifact_kind IN ('room_context', 'assessment_summary'))",
		"CHECK (coverage_policy IN ('room_summary', 'source_scope'))",
		"CREATE INDEX network_room_artifacts_room_id_idx",
		"CREATE INDEX network_room_artifacts_case_id_idx",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(sql, snippet) {
			t.Fatalf("network-room artifact migration missing required snippet %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"case_note_body",
		"foreign_private",
		"foreign_edd",
		"flag" + "_value",
		"secret" + "_for_checker",
	} {
		if strings.Contains(strings.ToLower(sql), forbidden) {
			t.Fatalf("network-room artifact migration contains forbidden marker %q", forbidden)
		}
	}
}

func TestNetworkRoomDirtyCandidateMigrationDefinesBoundedQueue(t *testing.T) {
	sql := readMigration(t, "000011_network_room_dirty_candidates.sql")
	requiredSnippets := []string{
		"CREATE TABLE network_room_dirty_candidates",
		"id bigserial PRIMARY KEY",
		"entity_hint_norm text NOT NULL",
		"typology_hint_norm text NOT NULL",
		"reason text NOT NULL DEFAULT 'case_changed'",
		"status text NOT NULL DEFAULT 'pending'",
		"attempts integer NOT NULL DEFAULT 0",
		"locked_until timestamptz",
		"last_error text NOT NULL DEFAULT ''",
		"UNIQUE (entity_hint_norm, typology_hint_norm)",
		"CHECK (status IN ('pending', 'processing', 'done'))",
		"CREATE INDEX IF NOT EXISTS network_room_dirty_candidates_pending_idx",
		"WHERE status = 'pending'",
		"CREATE INDEX IF NOT EXISTS network_room_dirty_candidates_expired_processing_idx",
		"WHERE status = 'processing'",
		"CREATE INDEX IF NOT EXISTS customers_entity_hint_norm_idx",
		"ON customers ((replace(lower(btrim(entity_hint)), ' ', '_')))",
		"CREATE INDEX IF NOT EXISTS cases_typology_hint_norm_idx",
		"ON cases ((replace(lower(btrim(typology_hint)), ' ', '_')))",
		"CREATE INDEX IF NOT EXISTS cases_customer_typology_idx",
		"CREATE INDEX IF NOT EXISTS network_room_cases_room_idx",
		"CREATE INDEX IF NOT EXISTS network_room_cases_case_idx",
		"CREATE INDEX IF NOT EXISTS audit_events_object_created_idx",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(sql, snippet) {
			t.Fatalf("network-room dirty candidate migration missing required snippet %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"flag" + "_value",
		"secret" + "_for_checker",
		"checker" + "_private",
		"case_notes",
		"edd_records",
		"confidential_comment",
	} {
		if strings.Contains(strings.ToLower(sql), forbidden) {
			t.Fatalf("network-room dirty candidate migration contains forbidden marker %q", forbidden)
		}
	}
}

func readMigration(t *testing.T, name string) string {
	t.Helper()
	root := repositoryRoot(t)
	content, err := os.ReadFile(filepath.Join(root, "migrations", name))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	return string(content)
}

func readAllMigrations(t *testing.T) string {
	t.Helper()
	root := repositoryRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "migrations"))
	if err != nil {
		t.Fatalf("read migrations directory: %v", err)
	}
	var builder strings.Builder
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		builder.WriteString(readMigration(t, entry.Name()))
		builder.WriteByte('\n')
	}
	return builder.String()
}
