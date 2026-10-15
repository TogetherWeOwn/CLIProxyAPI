package auth

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Credits pool classifications for a credential's post-plan-quota credits.
// The classification is operator configuration (auth-file "credits" field),
// never inferred from upstream signals: a bare "has credits" signal says
// nothing about whether spending those credits costs money.
const (
	CreditsKindFree = "free"
	CreditsKindPaid = "paid"
)

// AttributeCredits is the per-credential credits pool classification key.
// Supported values: "free" and "paid". Absent means unclassified, and
// unclassified credits are never spent by quota-aware routing.
const AttributeCredits = "credits"

// QuotaAwarePolicy bounds quota-aware credential selection.
type QuotaAwarePolicy struct {
	// AllowPaidCredits permits selecting weekly-exhausted credentials whose
	// credits pool is classified "paid", as a last resort after plan,
	// free-credit, and unknown-telemetry candidates. Default false: paid
	// credits are never spent.
	AllowPaidCredits bool
	// StaleAfter bounds telemetry age. A snapshot older than this (with no
	// reset in between) is unknown telemetry: it does not manufacture
	// headroom. Values <= 0 use the default.
	StaleAfter time.Duration
	// Hysteresis is the remaining-weekly-fraction lead a challenger needs
	// before selection moves off the incumbent credential, which prevents
	// oscillation when fractions are close. Values < 0 are treated as 0.
	Hysteresis float64
}

const defaultQuotaStaleAfter = 15 * time.Minute

func (p QuotaAwarePolicy) normalizedQuotaAwarePolicy() QuotaAwarePolicy {
	if p.StaleAfter <= 0 {
		p.StaleAfter = defaultQuotaStaleAfter
	}
	if p.Hysteresis < 0 {
		p.Hysteresis = 0
	}
	if p.Hysteresis > 1 {
		p.Hysteresis = 1
	}
	return p
}

// quotaClass ranks candidate pools. Lower is selected first.
type quotaClass int

const (
	quotaClassPlan quotaClass = iota
	quotaClassFreeCredits
	quotaClassUnknown
	quotaClassPaidCredits
	quotaClassExhausted
)

type quotaEvaluation struct {
	Class           quotaClass
	WeeklyRemaining float64
	CreditsBalance  float64
	WeeklyResetAt   time.Time
	Reason          string
}

// creditsKindOf returns the configured credits pool classification for an
// auth: Attributes win over Metadata, mirroring AuthKind resolution.
func creditsKindOf(auth *Auth) string {
	if auth == nil {
		return ""
	}
	if kind := normalizeCreditsKind(authAttribute(auth, AttributeCredits)); kind != "" {
		return kind
	}
	return normalizeCreditsKind(authMetadataString(auth, AttributeCredits))
}

func normalizeCreditsKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case CreditsKindFree:
		return CreditsKindFree
	case CreditsKindPaid:
		return CreditsKindPaid
	default:
		return ""
	}
}

// ValidateAuthCredits validates every explicit credential credits source.
func ValidateAuthCredits(auth *Auth) error {
	if auth == nil {
		return nil
	}
	if raw, ok := auth.Attributes[AttributeCredits]; ok && strings.TrimSpace(raw) != "" && normalizeCreditsKind(raw) == "" {
		return fmt.Errorf("invalid attributes credits: must be %q or %q", CreditsKindFree, CreditsKindPaid)
	}
	if raw, ok := auth.Metadata[AttributeCredits]; ok {
		text, isString := raw.(string)
		if !isString {
			return fmt.Errorf("invalid metadata credits: must be a string")
		}
		if strings.TrimSpace(text) != "" && normalizeCreditsKind(text) == "" {
			return fmt.Errorf("invalid metadata credits: must be %q or %q", CreditsKindFree, CreditsKindPaid)
		}
	}
	return nil
}

// ApplyAuthCreditsMetadata validates the auth and applies a source metadata
// credits classification, mirroring ApplyAuthWeightMetadata.
func ApplyAuthCreditsMetadata(auth *Auth, metadata map[string]any) error {
	if err := ValidateAuthCredits(auth); err != nil {
		return err
	}
	if auth == nil || metadata == nil {
		return nil
	}
	raw, ok := metadata[AttributeCredits]
	if !ok {
		return nil
	}
	text, isString := raw.(string)
	if !isString {
		return fmt.Errorf("invalid metadata credits: must be a string")
	}
	kind := normalizeCreditsKind(text)
	if kind == "" {
		if strings.TrimSpace(text) == "" {
			return nil
		}
		return fmt.Errorf("invalid metadata credits: must be %q or %q", CreditsKindFree, CreditsKindPaid)
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes[AttributeCredits] = kind
	return nil
}

type quotaWindow struct {
	usedPercent   float64
	windowMinutes int64
	resetAt       time.Time
	hasReset      bool
}

// evaluateQuota classifies one credential from its passive quota snapshot.
// It is pure: all times derive from the supplied now and the snapshot's
// ObservedAt, so tests are deterministic.
func evaluateQuota(auth *Auth, now time.Time, policy QuotaAwarePolicy) quotaEvaluation {
	policy = policy.normalizedQuotaAwarePolicy()
	if auth == nil {
		return quotaEvaluation{Class: quotaClassExhausted, Reason: "no-auth"}
	}
	signals := make(map[string]string, len(auth.Quota.Signals))
	for key, value := range auth.Quota.Signals {
		signals[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	observedAt := auth.Quota.ObservedAt
	fresh := !observedAt.IsZero() && now.Sub(observedAt) <= policy.StaleAfter

	windows := collectQuotaWindows(signals, observedAt)
	var weekly, short *quotaWindow
	for i := range windows {
		window := &windows[i]
		if window.windowMinutes >= 1440 && (weekly == nil || window.windowMinutes > weekly.windowMinutes) {
			weekly = window
		}
		if window.windowMinutes <= 720 && (short == nil || window.windowMinutes < short.windowMinutes) {
			short = window
		}
	}

	weeklyExhausted := false
	weeklyRemaining := 0.0
	var weeklyReset time.Time
	switch {
	case weekly != nil:
		if weekly.hasReset {
			weeklyReset = weekly.resetAt
		}
		if !fresh && !(weekly.usedPercent >= 100 && weekly.hasReset && now.Before(weekly.resetAt)) {
			// A stale snapshot is unknown telemetry, eligible only via the
			// bounded fallback. One exception: a 100%-used snapshot whose
			// reset is still in the future stays exhausted below, because
			// the window cannot have recovered before that reset. A
			// snapshot taken before a reset that has since passed is the
			// opposite case: the window has rolled over, so it is unknown.
			return quotaEvaluation{Class: quotaClassUnknown, WeeklyResetAt: weeklyReset, Reason: "stale-telemetry"}
		}
		weeklyRemaining = 1 - weekly.usedPercent/100
		if weeklyRemaining < 0 {
			weeklyRemaining = 0
		}
		weeklyExhausted = weekly.usedPercent >= 100
	case fresh && claudeWeeklyRejected(signals):
		weeklyExhausted = true
	case !fresh:
		return quotaEvaluation{Class: quotaClassUnknown, Reason: "stale-telemetry"}
	default:
		if short != nil && short.usedPercent >= 100 {
			return quotaEvaluation{Class: quotaClassExhausted, Reason: "five-hour-exhausted"}
		}
		return quotaEvaluation{Class: quotaClassUnknown, Reason: "no-weekly-telemetry"}
	}
	if fresh && codexLimitReached(signals) {
		weeklyExhausted = true
		weeklyRemaining = 0
	}

	// The short-window (5h) guard applies to every class, including the
	// credits tier: a credential at its short-window limit is not routed to
	// until that window recovers, whatever its weekly state.
	if short != nil && short.usedPercent >= 100 {
		return quotaEvaluation{Class: quotaClassExhausted, WeeklyRemaining: weeklyRemaining, WeeklyResetAt: weeklyReset, Reason: "five-hour-exhausted"}
	}

	if !weeklyExhausted {
		if weekly == nil {
			return quotaEvaluation{Class: quotaClassUnknown, Reason: "no-weekly-telemetry"}
		}
		return quotaEvaluation{Class: quotaClassPlan, WeeklyRemaining: weeklyRemaining, WeeklyResetAt: weeklyReset, Reason: "plan"}
	}

	// Weekly plan quota is exhausted. Credits are capacity only when the
	// operator classified the pool AND fresh telemetry proves a spendable
	// balance. "Has credits" alone is never capacity evidence.
	kind := creditsKindOf(auth)
	if kind == "" {
		return quotaEvaluation{Class: quotaClassExhausted, WeeklyResetAt: weeklyReset, Reason: "weekly-exhausted-credits-unclassified"}
	}
	if !fresh {
		return quotaEvaluation{Class: quotaClassExhausted, WeeklyResetAt: weeklyReset, Reason: "weekly-exhausted-credits-stale"}
	}
	balance, hasBalance := creditsBalance(signals)
	if !hasBalance {
		return quotaEvaluation{Class: quotaClassExhausted, WeeklyResetAt: weeklyReset, Reason: "weekly-exhausted-credits-unproven"}
	}
	if kind == CreditsKindFree {
		return quotaEvaluation{Class: quotaClassFreeCredits, CreditsBalance: balance, WeeklyResetAt: weeklyReset, Reason: "free-credits"}
	}
	if policy.AllowPaidCredits {
		return quotaEvaluation{Class: quotaClassPaidCredits, CreditsBalance: balance, WeeklyResetAt: weeklyReset, Reason: "paid-credits-allowed"}
	}
	return quotaEvaluation{Class: quotaClassExhausted, WeeklyResetAt: weeklyReset, Reason: "weekly-exhausted-paid-credits-excluded"}
}

// collectQuotaWindows parses the Codex primary/secondary windows out of a
// lower-cased signal snapshot. Windows are classified by their duration by
// the caller, never by namespace name: providers swap which namespace is
// the weekly window.
func collectQuotaWindows(signals map[string]string, observedAt time.Time) []quotaWindow {
	var windows []quotaWindow
	for _, namespace := range []string{"primary", "secondary"} {
		prefix := "x-codex-" + namespace + "-"
		usedRaw, ok := signals[prefix+"used-percent"]
		if !ok {
			continue
		}
		used, errUsed := strconv.ParseFloat(usedRaw, 64)
		if errUsed != nil || used < 0 || used > 100 {
			continue
		}
		minutes, errMinutes := strconv.ParseInt(signals[prefix+"window-minutes"], 10, 64)
		if errMinutes != nil || minutes <= 0 {
			continue
		}
		window := quotaWindow{usedPercent: used, windowMinutes: minutes}
		if resetAtRaw, ok := signals[prefix+"reset-at"]; ok {
			if seconds, errParse := strconv.ParseInt(resetAtRaw, 10, 64); errParse == nil && seconds > 0 {
				window.resetAt = time.Unix(seconds, 0)
				window.hasReset = true
			}
		}
		if !window.hasReset {
			if afterRaw, ok := signals[prefix+"reset-after-seconds"]; ok && !observedAt.IsZero() {
				if seconds, errParse := strconv.ParseInt(afterRaw, 10, 64); errParse == nil && seconds >= 0 {
					window.resetAt = observedAt.Add(time.Duration(seconds) * time.Second)
					window.hasReset = true
				}
			}
		}
		windows = append(windows, window)
	}
	return windows
}

func codexLimitReached(signals map[string]string) bool {
	if strings.EqualFold(signals["x-codex-limit-reached"], "true") {
		return true
	}
	if allowed, ok := signals["x-codex-allowed"]; ok && strings.EqualFold(allowed, "false") {
		return true
	}
	return false
}

func claudeWeeklyRejected(signals map[string]string) bool {
	for key, value := range signals {
		if strings.HasPrefix(key, "anthropic-ratelimit-unified-") && strings.Contains(key, "-7d-") &&
			strings.HasSuffix(key, "-status") && strings.EqualFold(value, "rejected") {
			return true
		}
	}
	return false
}

// creditsBalance proves a spendable credits balance from fresh signals.
// Unlimited credits count as a large balance; "has credits" without a
// balance proves nothing and returns false.
func creditsBalance(signals map[string]string) (float64, bool) {
	if strings.EqualFold(signals["x-codex-credits-unlimited"], "true") {
		return 1e15, true
	}
	if has, ok := signals["x-codex-credits-has-credits"]; ok && strings.EqualFold(has, "false") {
		return 0, false
	}
	raw, ok := signals["x-codex-credits-balance"]
	if !ok {
		return 0, false
	}
	balance, err := strconv.ParseFloat(raw, 64)
	if err != nil || balance <= 0 {
		return 0, false
	}
	return balance, true
}

// quotaSelectionState carries hysteresis and fallback cursors for one
// provider/model selection key.
type quotaSelectionState struct {
	lastPickedID   string
	fallbackLastID string
}

// pickQuotaAwareAuth selects from already-eligible candidates (disabled,
// cooldown, model and priority filtering happened upstream). Candidates in
// exhausted class are never returned; when every candidate is exhausted it
// returns nil so the caller surfaces unavailability instead of spending
// unclassified or paid credits.
func pickQuotaAwareAuth(candidates []*Auth, now time.Time, policy QuotaAwarePolicy, state *quotaSelectionState) *Auth {
	if state == nil || len(candidates) == 0 {
		return nil
	}
	policy = policy.normalizedQuotaAwarePolicy()
	sorted := append([]*Auth(nil), candidates...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	evals := make(map[string]quotaEvaluation, len(sorted))
	bestClass := quotaClassExhausted
	for _, candidate := range sorted {
		if candidate == nil {
			continue
		}
		eval := evaluateQuota(candidate, now, policy)
		evals[candidate.ID] = eval
		if eval.Class < bestClass {
			bestClass = eval.Class
		}
	}
	if bestClass == quotaClassExhausted {
		return nil
	}
	pool := make([]*Auth, 0, len(sorted))
	for _, candidate := range sorted {
		if candidate != nil && evals[candidate.ID].Class == bestClass {
			pool = append(pool, candidate)
		}
	}
	if len(pool) == 0 {
		return nil
	}

	if bestClass == quotaClassUnknown {
		// Bounded fallback: round-robin through unknown telemetry only when
		// no plan or free-credit candidate exists, so a cold or stale pool
		// can bootstrap fresh signals without manufacturing headroom.
		picked := pool[successorIndex(pool, state.fallbackLastID)]
		state.fallbackLastID = picked.ID
		state.lastPickedID = picked.ID
		return picked
	}

	score := func(auth *Auth) float64 {
		eval := evals[auth.ID]
		if bestClass == quotaClassPlan {
			return eval.WeeklyRemaining
		}
		return eval.CreditsBalance
	}
	var best *Auth
	for _, candidate := range pool {
		if best == nil || score(candidate) > score(best) {
			best = candidate
		}
	}
	picked := best
	if bestClass == quotaClassPlan && policy.Hysteresis > 0 && state.lastPickedID != "" {
		for _, candidate := range pool {
			if candidate.ID == state.lastPickedID {
				if score(best)-score(candidate) <= policy.Hysteresis {
					picked = candidate
				}
				break
			}
		}
	}
	state.lastPickedID = picked.ID
	return picked
}

// QuotaAwareSelector selects the eligible credential with the greatest
// remaining weekly quota fraction, so equal-workload traffic equalizes
// used fractions and a larger plan naturally serves proportionally more.
// Weekly-exhausted credentials fall to their configured credits pool only:
// free credits after plan quota, paid credits only when explicitly allowed.
type QuotaAwareSelector struct {
	Policy QuotaAwarePolicy

	mu      sync.Mutex
	states  map[string]*quotaSelectionState
	maxKeys int
}

// Pick implements Selector.
func (s *QuotaAwareSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, time.Now())
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	key := provider + ":" + canonicalModelKey(model)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states == nil {
		s.states = make(map[string]*quotaSelectionState)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}
	if _, ok := s.states[key]; !ok && len(s.states) >= limit {
		s.states = make(map[string]*quotaSelectionState)
	}
	state := s.states[key]
	if state == nil {
		state = &quotaSelectionState{}
		s.states[key] = state
	}
	picked := pickQuotaAwareAuth(available, time.Now(), s.Policy, state)
	if picked == nil {
		return nil, &Error{Code: "auth_unavailable", Message: "no auth available with plan quota or allowed credits"}
	}
	return picked, nil
}
