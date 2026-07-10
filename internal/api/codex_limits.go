// Package api — Codex usage/limits endpoint.
//
// Exposes GET /v1/codex/limits, returning Codex (ChatGPT-subscription) rate-limit
// windows in the same JSON shape that the Claude limits endpoint uses, so a single
// statusline client can render both. Data is sourced from ChatGPT's private
// /backend-api/wham/usage endpoint using each codex auth's OAuth access token.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const (
	codexUsageURL = "https://chatgpt.com/backend-api/wham/usage"
	// Matches the codex-tui UA the executor sends, to avoid Cloudflare 1010 blocks.
	codexUsageUserAgent = "codex-tui/0.135.0 (Mac OS 26.5.0; arm64) iTerm.app/3.6.10 (codex-tui; 0.135.0)"
	codexUsageCacheTTL  = 60 * time.Second
)

// whamUsage is the subset of /backend-api/wham/usage we care about.
type whamUsage struct {
	Email     string `json:"email"`
	PlanType  string `json:"plan_type"`
	RateLimit struct {
		Allowed       bool `json:"allowed"`
		LimitReached  bool `json:"limit_reached"`
		PrimaryWindow *struct {
			UsedPercent        float64 `json:"used_percent"`
			LimitWindowSeconds int64   `json:"limit_window_seconds"`
			ResetAfterSeconds  int64   `json:"reset_after_seconds"`
			ResetAt            int64   `json:"reset_at"`
		} `json:"primary_window"`
		SecondaryWindow *struct {
			UsedPercent        float64 `json:"used_percent"`
			LimitWindowSeconds int64   `json:"limit_window_seconds"`
			ResetAfterSeconds  int64   `json:"reset_after_seconds"`
			ResetAt            int64   `json:"reset_at"`
		} `json:"secondary_window"`
	} `json:"rate_limit"`
}

// limitWindow mirrors the Claude limits JSON so the statusline parses both identically.
type limitWindow struct {
	UtilizationPct float64 `json:"utilization_pct"`
	RemainingPct   float64 `json:"remaining_pct"`
	ResetsAt       string  `json:"resets_at,omitempty"`
	ResetsInSecs   int64   `json:"resets_in_seconds,omitempty"`
	ResetsInDays   float64 `json:"resets_in_days,omitempty"`
}

type credentialLimits struct {
	AuthID string `json:"auth_id"`
	Email  string `json:"email"`
	Plan   string `json:"plan"`
	Limits struct {
		FiveHour *limitWindow `json:"five_hour"`
		SevenDay *limitWindow `json:"seven_day"`
	} `json:"limits"`
	Quota struct {
		Exceeded bool `json:"exceeded"`
	} `json:"quota"`
}

type cachedCredential struct {
	at   time.Time
	data *credentialLimits
}

var (
	codexUsageCacheMu sync.Mutex
	codexUsageCache   = map[string]cachedCredential{}
)

// codexLimitsHandler serves GET /v1/codex/limits.
func (s *Server) codexLimitsHandler(c *gin.Context) {
	if s.handlers == nil || s.handlers.AuthManager == nil {
		c.JSON(http.StatusOK, gin.H{"credentials": []any{}})
		return
	}

	auths := s.handlers.AuthManager.List()
	creds := make([]*credentialLimits, 0, len(auths))

	for _, a := range auths {
		if a == nil || a.Disabled {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(a.Provider), "codex") {
			continue
		}
		cl := fetchCodexCredentialLimits(c.Request.Context(), s, a)
		if cl != nil {
			creds = append(creds, cl)
		}
	}

	c.JSON(http.StatusOK, gin.H{"credentials": creds})
}

// fetchCodexCredentialLimits returns cached-or-fresh limits for one codex auth.
// On any upstream failure it falls back to the last good cache entry, else nil.
func fetchCodexCredentialLimits(ctx context.Context, s *Server, a *coreauth.Auth) *credentialLimits {
	codexUsageCacheMu.Lock()
	if hit, ok := codexUsageCache[a.ID]; ok && time.Since(hit.at) < codexUsageCacheTTL {
		codexUsageCacheMu.Unlock()
		return hit.data
	}
	codexUsageCacheMu.Unlock()

	usage, err := fetchWhamUsage(ctx, s, a)
	if err != nil {
		// Serve stale cache on failure rather than dropping the credential.
		codexUsageCacheMu.Lock()
		defer codexUsageCacheMu.Unlock()
		if hit, ok := codexUsageCache[a.ID]; ok {
			return hit.data
		}
		return nil
	}

	cl := mapUsageToCredential(a, usage)

	codexUsageCacheMu.Lock()
	codexUsageCache[a.ID] = cachedCredential{at: time.Now(), data: cl}
	codexUsageCacheMu.Unlock()
	return cl
}

// fetchWhamUsage calls ChatGPT's private usage endpoint with the auth's OAuth token.
func fetchWhamUsage(ctx context.Context, s *Server, a *coreauth.Auth) (*whamUsage, error) {
	token := codexAccessToken(a)
	if token == "" {
		return nil, fmt.Errorf("codex auth %s has no access token", a.ID)
	}

	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, codexUsageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if accountID := codexMetaString(a, "account_id"); accountID != "" {
		req.Header.Set("ChatGPT-Account-Id", accountID)
	}
	req.Header.Set("User-Agent", codexUsageUserAgent)
	req.Header.Set("originator", "codex_cli_rs")
	req.Header.Set("Accept", "application/json")

	client := helps.NewUtlsHTTPClient(reqCtx, s.cfg, a, 0)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("wham/usage status %d", resp.StatusCode)
	}

	var usage whamUsage
	if err = json.NewDecoder(resp.Body).Decode(&usage); err != nil {
		return nil, err
	}
	return &usage, nil
}

// mapUsageToCredential converts wham/usage into the Claude-compatible limits shape.
func mapUsageToCredential(a *coreauth.Auth, u *whamUsage) *credentialLimits {
	cl := &credentialLimits{
		AuthID: a.ID,
		Email:  firstNonEmpty(u.Email, codexMetaString(a, "email")),
		Plan:   u.PlanType,
	}
	if p := u.RateLimit.PrimaryWindow; p != nil {
		cl.Limits.FiveHour = &limitWindow{
			UtilizationPct: p.UsedPercent,
			RemainingPct:   100 - p.UsedPercent,
			ResetsAt:       epochToISO(p.ResetAt),
			ResetsInSecs:   p.ResetAfterSeconds,
			ResetsInDays:   secsToDays(p.ResetAfterSeconds),
		}
	}
	if s := u.RateLimit.SecondaryWindow; s != nil {
		cl.Limits.SevenDay = &limitWindow{
			UtilizationPct: s.UsedPercent,
			RemainingPct:   100 - s.UsedPercent,
			ResetsAt:       epochToISO(s.ResetAt),
			ResetsInSecs:   s.ResetAfterSeconds,
			ResetsInDays:   secsToDays(s.ResetAfterSeconds),
		}
	}
	cl.Quota.Exceeded = u.RateLimit.LimitReached
	return cl
}

func codexAccessToken(a *coreauth.Auth) string {
	if a == nil {
		return ""
	}
	if a.Attributes != nil {
		if v := strings.TrimSpace(a.Attributes["api_key"]); v != "" {
			return v
		}
	}
	return codexMetaString(a, "access_token")
}

func codexMetaString(a *coreauth.Auth, key string) string {
	if a == nil || a.Metadata == nil {
		return ""
	}
	if v, ok := a.Metadata[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func epochToISO(epoch int64) string {
	if epoch <= 0 {
		return ""
	}
	return time.Unix(epoch, 0).UTC().Format(time.RFC3339)
}

// secsToDays converts a remaining-seconds count to days, rounded to one decimal.
func secsToDays(secs int64) float64 {
	if secs <= 0 {
		return 0
	}
	days := float64(secs) / 86400.0
	return float64(int64(days*10+0.5)) / 10
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
