package tests

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	acct "sentinel-aml/internal/account"
	alertrepo "sentinel-aml/internal/alert"
	"sentinel-aml/internal/auth"
	casework "sentinel-aml/internal/casework"
	"sentinel-aml/internal/config"
	cust "sentinel-aml/internal/customer"
	dbutil "sentinel-aml/internal/db"
	"sentinel-aml/internal/risk"
	txn "sentinel-aml/internal/transaction"
)

func TestWave03LivePostgresDomainRepositories(t *testing.T) {
	databaseURL := os.Getenv("SENTINEL_AML_INTEGRATION_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SENTINEL_AML_INTEGRATION_DATABASE_URL unset; skipping live PostgreSQL domain repository integration gate")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	database, err := dbutil.Open(ctx, config.DatabaseConfig{
		URL:            databaseURL,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	defer dbutil.Close(database)

	resetPublicSchema(t, ctx, database)
	migrations, err := dbutil.LoadMigrations(filepath.Join(repositoryRoot(t), "migrations"))
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	if err := dbutil.ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	authRepo := auth.NewRepository(database)
	owner, err := authRepo.CreateUser(ctx, auth.CreateUserParams{
		Username:     "owner-wave03",
		PasswordHash: "hash",
		Role:         auth.DefaultRole,
	})
	if err != nil {
		t.Fatalf("create owner user: %v", err)
	}
	otherOwner, err := authRepo.CreateUser(ctx, auth.CreateUserParams{
		Username:     "other-wave03",
		PasswordHash: "hash",
		Role:         auth.DefaultRole,
	})
	if err != nil {
		t.Fatalf("create other user: %v", err)
	}

	customerRepo := cust.NewRepository(database)
	accountRepo := acct.NewRepository(database)
	transactionRepo := txn.NewRepository(database)

	customer, err := customerRepo.Create(ctx, cust.CreateParams{
		OwnerUserID:        owner.ID,
		DisplayName:        "Wave 03 Customer",
		CustomerType:       "organization",
		Country:            "US",
		RegistrationNumber: "W03-001",
		RiskLevel:          "medium",
		EntityHint:         "integration",
	})
	if err != nil {
		t.Fatalf("create customer: %v", err)
	}
	account, err := accountRepo.Create(ctx, acct.CreateParams{
		OwnerUserID: owner.ID,
		CustomerID:  customer.ID,
		IBANLike:    "SAMLW03000001",
		Currency:    "USD",
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	transaction, err := transactionRepo.Create(ctx, txn.CreateParams{
		OwnerUserID:             owner.ID,
		AccountID:               account.ID,
		CounterpartyName:        "Counterparty",
		CounterpartyCountry:     "GB",
		CounterpartyFingerprint: "counterparty-fp",
		Amount:                  "42.50",
		Currency:                "USD",
		Direction:               "outbound",
		Purpose:                 "invoice",
		TraceID:                 "trace-wave03-001",
	})
	if err != nil {
		t.Fatalf("create transaction: %v", err)
	}

	customers, err := customerRepo.ListByOwner(ctx, owner.ID)
	if err != nil || len(customers) != 1 {
		t.Fatalf("list customers: len=%d err=%v", len(customers), err)
	}
	accounts, err := accountRepo.ListByOwner(ctx, owner.ID)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("list accounts: len=%d err=%v", len(accounts), err)
	}
	transactions, err := transactionRepo.ListByOwner(ctx, owner.ID)
	if err != nil || len(transactions) != 1 {
		t.Fatalf("list transactions: len=%d err=%v", len(transactions), err)
	}

	if _, err := customerRepo.GetByOwner(ctx, otherOwner.ID, customer.ID); err == nil {
		t.Fatal("cross-owner customer lookup should fail closed")
	}
	if _, err := accountRepo.GetByOwner(ctx, otherOwner.ID, account.ID); err == nil {
		t.Fatal("cross-owner account lookup should fail closed")
	}
	if _, err := transactionRepo.GetByOwner(ctx, otherOwner.ID, transaction.ID); err == nil {
		t.Fatal("cross-owner transaction lookup should fail closed")
	}
}

func TestWave04LivePostgresInvestigationRepositories(t *testing.T) {
	databaseURL := os.Getenv("SENTINEL_AML_INTEGRATION_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SENTINEL_AML_INTEGRATION_DATABASE_URL unset; skipping live PostgreSQL investigation repository integration gate")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	database, err := dbutil.Open(ctx, config.DatabaseConfig{
		URL:            databaseURL,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	defer dbutil.Close(database)

	resetPublicSchema(t, ctx, database)
	migrations, err := dbutil.LoadMigrations(filepath.Join(repositoryRoot(t), "migrations"))
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	if err := dbutil.ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	authRepo := auth.NewRepository(database)
	owner, err := authRepo.CreateUser(ctx, auth.CreateUserParams{
		Username:     "owner-wave04",
		PasswordHash: "hash",
		Role:         auth.DefaultRole,
	})
	if err != nil {
		t.Fatalf("create owner user: %v", err)
	}
	otherOwner, err := authRepo.CreateUser(ctx, auth.CreateUserParams{
		Username:     "other-wave04",
		PasswordHash: "hash",
		Role:         auth.DefaultRole,
	})
	if err != nil {
		t.Fatalf("create other user: %v", err)
	}

	customerRepo := cust.NewRepository(database)
	accountRepo := acct.NewRepository(database)
	transactionRepo := txn.NewRepository(database)
	alertRepo := alertrepo.NewRepository(database)
	caseRepo := casework.NewRepository(database)

	customer, err := customerRepo.Create(ctx, cust.CreateParams{
		OwnerUserID:        owner.ID,
		DisplayName:        "Wave 04 Customer",
		CustomerType:       "organization",
		Country:            "US",
		RegistrationNumber: "W04-001",
		RiskLevel:          "medium",
		EntityHint:         "integration",
	})
	if err != nil {
		t.Fatalf("create customer: %v", err)
	}
	account, err := accountRepo.Create(ctx, acct.CreateParams{
		OwnerUserID: owner.ID,
		CustomerID:  customer.ID,
		IBANLike:    "SAMLW04000001",
		Currency:    "USD",
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	transaction, err := transactionRepo.Create(ctx, txn.CreateParams{
		OwnerUserID:             owner.ID,
		AccountID:               account.ID,
		CounterpartyName:        "Counterparty",
		CounterpartyCountry:     "GB",
		CounterpartyFingerprint: "counterparty-fp",
		Amount:                  "42.50",
		Currency:                "USD",
		Direction:               "outbound",
		Purpose:                 "invoice",
		TraceID:                 "trace-wave04-001",
	})
	if err != nil {
		t.Fatalf("create transaction: %v", err)
	}

	alert, err := alertRepo.Create(ctx, alertrepo.CreateParams{
		OwnerUserID:   owner.ID,
		TransactionID: transaction.ID,
		RuleCode:      "HIGH_RISK_COUNTERPARTY",
		RiskScore:     80,
		TypologyHint:  "sanctions",
	})
	if err != nil {
		t.Fatalf("create alert: %v", err)
	}
	claimed, err := alertRepo.Claim(ctx, alertrepo.ClaimParams{
		OwnerUserID:    owner.ID,
		AlertID:        alert.ID,
		AssignedUserID: owner.ID,
	})
	if err != nil {
		t.Fatalf("claim alert: %v", err)
	}
	if !claimed.AssignedUserID.Valid || claimed.AssignedUserID.Int64 != owner.ID {
		t.Fatalf("alert assignment mismatch: %#v", claimed)
	}
	triaged, err := alertRepo.Triage(ctx, alertrepo.TriageParams{
		OwnerUserID: owner.ID,
		AlertID:     alert.ID,
		Status:      "TRIAGED",
	})
	if err != nil {
		t.Fatalf("triage alert: %v", err)
	}
	if triaged.Status != "TRIAGED" {
		t.Fatalf("alert status mismatch: %#v", triaged)
	}

	investigationCase, err := caseRepo.CreateFromAlert(ctx, casework.CreateCaseParams{
		OwnerUserID:   owner.ID,
		AlertID:       alert.ID,
		PublicSummary: "Review high-risk counterparty",
	})
	if err != nil {
		t.Fatalf("create case: %v", err)
	}
	updatedCase, err := caseRepo.UpdateStatus(ctx, casework.UpdateCaseStatusParams{
		OwnerUserID: owner.ID,
		CaseID:      investigationCase.ID,
		Status:      "UNDER_REVIEW",
	})
	if err != nil {
		t.Fatalf("update case status: %v", err)
	}
	if updatedCase.Status != "UNDER_REVIEW" {
		t.Fatalf("case status mismatch: %#v", updatedCase)
	}

	note, err := caseRepo.CreateNote(ctx, casework.CreateNoteParams{
		OwnerUserID:  owner.ID,
		CaseID:       investigationCase.ID,
		AuthorUserID: owner.ID,
		Visibility:   "private",
		Body:         "Normal private analyst note",
	})
	if err != nil {
		t.Fatalf("create case note: %v", err)
	}
	notes, err := caseRepo.ListNotesByOwner(ctx, owner.ID, investigationCase.ID)
	if err != nil || len(notes) != 1 || notes[0].ID != note.ID {
		t.Fatalf("list case notes: len=%d err=%v notes=%#v", len(notes), err, notes)
	}

	if _, err := alertRepo.GetByOwner(ctx, otherOwner.ID, alert.ID); err == nil {
		t.Fatal("cross-owner alert lookup should fail closed")
	}
	if _, err := caseRepo.GetByOwner(ctx, otherOwner.ID, investigationCase.ID); err == nil {
		t.Fatal("cross-owner case lookup should fail closed")
	}
	if _, err := caseRepo.ListNotesByOwner(ctx, otherOwner.ID, investigationCase.ID); err == nil {
		t.Fatal("cross-owner note lookup should fail closed")
	}
}

func TestWave04LivePostgresRiskAlertGeneration(t *testing.T) {
	databaseURL := os.Getenv("SENTINEL_AML_INTEGRATION_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SENTINEL_AML_INTEGRATION_DATABASE_URL unset; skipping live PostgreSQL risk/alert integration gate")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	database, err := dbutil.Open(ctx, config.DatabaseConfig{
		URL:            databaseURL,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	defer dbutil.Close(database)

	resetPublicSchema(t, ctx, database)
	migrations, err := dbutil.LoadMigrations(filepath.Join(repositoryRoot(t), "migrations"))
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	if err := dbutil.ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	authRepo := auth.NewRepository(database)
	owner, err := authRepo.CreateUser(ctx, auth.CreateUserParams{
		Username:     "owner-wave04-risk",
		PasswordHash: "hash",
		Role:         auth.DefaultRole,
	})
	if err != nil {
		t.Fatalf("create owner user: %v", err)
	}
	otherOwner, err := authRepo.CreateUser(ctx, auth.CreateUserParams{
		Username:     "other-wave04-risk",
		PasswordHash: "hash",
		Role:         auth.DefaultRole,
	})
	if err != nil {
		t.Fatalf("create other user: %v", err)
	}

	customerRepo := cust.NewRepository(database)
	accountRepo := acct.NewRepository(database)
	transactionRepo := txn.NewRepository(database)
	alertRepo := alertrepo.NewRepository(database)
	riskService := risk.NewService(transactionRepo, alertRepo)

	customer, err := customerRepo.Create(ctx, cust.CreateParams{
		OwnerUserID:        owner.ID,
		DisplayName:        "Wave 04 Risk Customer",
		CustomerType:       "organization",
		Country:            "US",
		RegistrationNumber: "W04-RISK-001",
	})
	if err != nil {
		t.Fatalf("create customer: %v", err)
	}
	account, err := accountRepo.Create(ctx, acct.CreateParams{
		OwnerUserID: owner.ID,
		CustomerID:  customer.ID,
		IBANLike:    "SAMLW04RISK001",
		Currency:    "USD",
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	transaction, err := transactionRepo.Create(ctx, txn.CreateParams{
		OwnerUserID:             owner.ID,
		AccountID:               account.ID,
		CounterpartyName:        "Risk Counterparty",
		CounterpartyCountry:     "GB",
		CounterpartyFingerprint: "alpha",
		Amount:                  "60000.00",
		Currency:                "USD",
		Direction:               "outbound",
		Purpose:                 "invoice",
		TraceID:                 "trace-wave04-risk-001",
	})
	if err != nil {
		t.Fatalf("create transaction: %v", err)
	}

	first, err := riskService.ScoreTransaction(ctx, owner.ID, transaction.ID)
	if err != nil {
		t.Fatalf("first score transaction: %v", err)
	}
	second, err := riskService.ScoreTransaction(ctx, owner.ID, transaction.ID)
	if err != nil {
		t.Fatalf("second score transaction: %v", err)
	}
	if !first.Suspicious || !first.AlertCreated || second.AlertCreated {
		t.Fatalf("risk decisions should be suspicious and idempotent: first=%#v second=%#v", first, second)
	}
	if first.Transaction.RiskScore != first.RiskScore {
		t.Fatalf("transaction risk score not updated: %#v", first)
	}

	alerts, err := alertRepo.ListByOwner(ctx, owner.ID)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("list owner alerts: len=%d err=%v alerts=%#v", len(alerts), err, alerts)
	}
	if alerts[0].RuleCode != risk.RuleDeterministicThreshold || alerts[0].RiskScore != first.RiskScore {
		t.Fatalf("alert mismatch: %#v decision=%#v", alerts[0], first)
	}
	if _, err := riskService.ScoreTransaction(ctx, otherOwner.ID, transaction.ID); err == nil {
		t.Fatal("cross-owner scoring should fail closed")
	}
	if _, err := alertRepo.GetByOwner(ctx, otherOwner.ID, alerts[0].ID); err == nil {
		t.Fatal("cross-owner alert read should fail closed")
	}
}

func resetPublicSchema(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	if _, err := database.ExecContext(ctx, `DROP SCHEMA IF EXISTS public CASCADE`); err != nil {
		t.Fatalf("drop public schema: %v", err)
	}
	if _, err := database.ExecContext(ctx, `CREATE SCHEMA public`); err != nil {
		t.Fatalf("create public schema: %v", err)
	}
}
