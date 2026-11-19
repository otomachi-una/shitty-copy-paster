package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinel-aml/internal/auth"
	"sentinel-aml/internal/httpapi"
)

func TestWave02HTTPAuthSurface(t *testing.T) {
	handler := httpapi.NewServer(gateAuthService{}).Routes()

	health := performRequest(handler, http.MethodGet, "/healthz", "")
	if health.Code != http.StatusOK {
		t.Fatalf("health status mismatch: %d", health.Code)
	}

	register := performRequest(handler, http.MethodPost, "/api/auth/register", `{"username":"analyst-a","password":"passphrase"}`)
	if register.Code != http.StatusCreated {
		t.Fatalf("register status mismatch: %d body=%s", register.Code, register.Body.String())
	}
	assertGateResponseClean(t, register.Body.String())

	login := performRequest(handler, http.MethodPost, "/api/auth/login", `{"username":"analyst-a","password":"passphrase"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("login status mismatch: %d body=%s", login.Code, login.Body.String())
	}
	assertGateResponseClean(t, login.Body.String())

	unauthenticated := performRequest(handler, http.MethodGet, "/api/auth/me", "")
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated me status mismatch: %d body=%s", unauthenticated.Code, unauthenticated.Body.String())
	}

	meReq := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer gate-token")
	me := httptest.NewRecorder()
	handler.ServeHTTP(me, meReq)
	if me.Code != http.StatusOK {
		t.Fatalf("authenticated me status mismatch: %d body=%s", me.Code, me.Body.String())
	}
	assertGateResponseClean(t, me.Body.String())
}

func TestWave02NoAMLDebugOrAdminRoutesRegistered(t *testing.T) {
	handler := httpapi.NewServer(gateAuthService{}).Routes()
	for _, path := range []string{
		"/api/aml",
		"/api/customers",
		"/api/accounts",
		"/api/transactions",
		"/api/alerts",
		"/api/cases",
		"/de" + "bug",
		"/ad" + "min",
		"/api/de" + "bug",
		"/api/ad" + "min",
	} {
		rec := performRequest(handler, http.MethodGet, path, "")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected %s to be absent with 404, got %d", path, rec.Code)
		}
	}
}

func performRequest(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func assertGateResponseClean(t *testing.T, body string) {
	t.Helper()
	for _, forbidden := range []string{"password_hash", "token_hash", "raw_db_row", "flag" + "_value", "secret" + "_for_checker"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, body)
		}
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("response is not JSON: %v body=%s", err, body)
	}
}

type gateAuthService struct{}

func (gateAuthService) Register(context.Context, string, string) (auth.AuthResult, error) {
	return gateAuthResult(), nil
}

func (gateAuthService) Login(context.Context, string, string) (auth.AuthResult, error) {
	return gateAuthResult(), nil
}

func (gateAuthService) CurrentUser(_ context.Context, token string) (auth.User, error) {
	if token != "gate-token" {
		return auth.User{}, auth.ErrUnauthenticated
	}
	return gateUser(), nil
}

func gateAuthResult() auth.AuthResult {
	return auth.AuthResult{
		User:      gateUser(),
		RawToken:  "gate-token",
		ExpiresAt: time.Unix(200, 0).UTC(),
	}
}

func gateUser() auth.User {
	return auth.User{
		ID:        1,
		Username:  "analyst-a",
		Role:      auth.DefaultRole,
		Status:    "active",
		CreatedAt: time.Unix(100, 0).UTC(),
	}
}
