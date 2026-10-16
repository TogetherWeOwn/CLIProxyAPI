package auth

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func quotaTestAuth(id string, weeklyUsed float64) *Auth {
	now := time.Now()
	return &Auth{
		ID:       id,
		Provider: "codex",
		Status:   StatusActive,
		Quota: QuotaState{
			ObservedAt: now,
			Signals: map[string]string{
				"X-Codex-Primary-Used-Percent":     "10",
				"X-Codex-Primary-Window-Minutes":   "300",
				"X-Codex-Primary-Reset-At":         fmt.Sprint(now.Add(2 * time.Hour).Unix()),
				"X-Codex-Secondary-Used-Percent":   fmt.Sprint(weeklyUsed),
				"X-Codex-Secondary-Window-Minutes": "10080",
				"X-Codex-Secondary-Reset-At":       fmt.Sprint(now.Add(48 * time.Hour).Unix()),
				"X-Codex-Credits-Has-Credits":      "false",
				"X-Codex-Credits-Balance":          "0",
			},
		},
	}
}

func setWeeklyUsed(auth *Auth, weeklyUsed float64) {
	auth.Quota.Signals["X-Codex-Secondary-Used-Percent"] = fmt.Sprint(weeklyUsed)
	auth.Quota.ObservedAt = time.Now()
}

func pickQuota(t *testing.T, selector *QuotaAwareSelector, auths ...*Auth) *Auth {
	t.Helper()
	got, err := selector.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil {
		t.Fatal("Pick() auth = nil")
	}
	return got
}

func TestQuotaAwarePicksGreatestRemainingWeeklyFraction(t *testing.T) {
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	low := quotaTestAuth("a-low-remaining", 80)
	high := quotaTestAuth("b-high-remaining", 20)
	if got := pickQuota(t, selector, low, high); got.ID != high.ID {
		t.Fatalf("Pick() = %q, want %q (greatest remaining weekly fraction)", got.ID, high.ID)
	}
}

func TestQuotaAwareEqualPlansEqualize(t *testing.T) {
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	a := quotaTestAuth("a", 0)
	b := quotaTestAuth("b", 0)
	used := map[string]float64{"a": 0, "b": 0}
	counts := map[string]int{}
	for i := 0; i < 200; i++ {
		got := pickQuota(t, selector, a, b)
		counts[got.ID]++
		used[got.ID] += 1
		setWeeklyUsed(a, used["a"])
		setWeeklyUsed(b, used["b"])
	}
	for id, count := range counts {
		if count < 80 || count > 120 {
			t.Fatalf("equal plans: %q picks = %d, want within [80,120] (counts=%v)", id, count, counts)
		}
	}
}

func TestQuotaAwareFourTimesPlanGetsAboutFourTimesTraffic(t *testing.T) {
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	small := quotaTestAuth("a-small", 0)
	large := quotaTestAuth("b-large", 0)
	used := map[string]float64{small.ID: 0, large.ID: 0}
	counts := map[string]int{}
	for i := 0; i < 400; i++ {
		got := pickQuota(t, selector, small, large)
		counts[got.ID]++
		if got.ID == small.ID {
			used[got.ID] += 1
		} else {
			used[got.ID] += 0.25
		}
		setWeeklyUsed(small, used[small.ID])
		setWeeklyUsed(large, used[large.ID])
	}
	ratio := float64(counts[large.ID]) / float64(counts[small.ID])
	if ratio < 3 || ratio > 5 {
		t.Fatalf("4x plan traffic ratio = %.2f, want within [3,5] (counts=%v)", ratio, counts)
	}
}

func TestQuotaAwareWeeklyExhaustedNeverFallsThroughToPaidCredits(t *testing.T) {
	policy := QuotaAwarePolicy{Hysteresis: 0}
	exhausted := quotaTestAuth("a-exhausted", 100)
	exhausted.Quota.Signals["X-Codex-Credits-Has-Credits"] = "true"
	exhausted.Quota.Signals["X-Codex-Credits-Balance"] = "500"
	healthy := quotaTestAuth("b-healthy", 50)

	selector := &QuotaAwareSelector{Policy: policy}
	if got := pickQuota(t, selector, exhausted, healthy); got.ID != healthy.ID {
		t.Fatalf("Pick() = %q, want healthy credential; weekly-exhausted must not leak to credits", got.ID)
	}

	// Alone, with no credits classification at all: unavailable, not credits.
	alone := &QuotaAwareSelector{Policy: policy}
	if _, err := alone.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{}, []*Auth{exhausted}); err == nil {
		t.Fatal("Pick() with only weekly-exhausted unclassified-credit credential succeeded, want error")
	}

	// Explicitly paid-classified credits stay excluded unless allowed.
	paid := quotaTestAuth("c-paid", 100)
	paid.Attributes = map[string]string{AttributeCredits: CreditsKindPaid}
	paid.Quota.Signals["X-Codex-Credits-Has-Credits"] = "true"
	paid.Quota.Signals["X-Codex-Credits-Balance"] = "500"
	paidSelector := &QuotaAwareSelector{Policy: policy}
	if _, err := paidSelector.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{}, []*Auth{paid}); err == nil {
		t.Fatal("Pick() with only paid-credit credential succeeded while paid credits not allowed, want error")
	}

	allowed := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0, AllowPaidCredits: true}}
	if got := pickQuota(t, allowed, paid); got.ID != paid.ID {
		t.Fatalf("Pick() with paid credits explicitly allowed = %q, want %q", got.ID, paid.ID)
	}
}

func TestQuotaAwareFreeCreditsUsedOnlyAfterPlanQuota(t *testing.T) {
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	onCredits := quotaTestAuth("a-credits", 100)
	onCredits.Attributes = map[string]string{AttributeCredits: CreditsKindFree}
	onCredits.Quota.Signals["X-Codex-Credits-Has-Credits"] = "true"
	onCredits.Quota.Signals["X-Codex-Credits-Balance"] = "1000"
	onPlan := quotaTestAuth("b-plan", 90)

	if got := pickQuota(t, selector, onCredits, onPlan); got.ID != onPlan.ID {
		t.Fatalf("Pick() = %q, want plan credential before credit-backed credential", got.ID)
	}
	setWeeklyUsed(onPlan, 100)
	if got := pickQuota(t, selector, onCredits, onPlan); got.ID != onCredits.ID {
		t.Fatalf("Pick() = %q, want free-credit credential after plan quota exhausted", got.ID)
	}
}

func TestQuotaAwareFiveHourExhaustedIsGuarded(t *testing.T) {
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	guarded := quotaTestAuth("a-5h-exhausted", 10)
	guarded.Quota.Signals["X-Codex-Primary-Used-Percent"] = "100"
	healthy := quotaTestAuth("b-healthy", 50)
	if got := pickQuota(t, selector, guarded, healthy); got.ID != healthy.ID {
		t.Fatalf("Pick() = %q, want healthy; 5h-exhausted credential must be guarded", got.ID)
	}
	alone := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	if _, err := alone.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{}, []*Auth{guarded}); err == nil {
		t.Fatal("Pick() with only 5h-exhausted credential succeeded, want error")
	}
}

func TestQuotaAwareShortWindowOnlyExhaustedIsGuarded(t *testing.T) {
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	guarded := quotaTestAuth("a-short-only", 0)
	delete(guarded.Quota.Signals, "X-Codex-Secondary-Used-Percent")
	delete(guarded.Quota.Signals, "X-Codex-Secondary-Window-Minutes")
	delete(guarded.Quota.Signals, "X-Codex-Secondary-Reset-At")
	guarded.Quota.Signals["X-Codex-Primary-Used-Percent"] = "100"
	healthy := quotaTestAuth("b-healthy", 50)
	if got := pickQuota(t, selector, guarded, healthy); got.ID != healthy.ID {
		t.Fatalf("Pick() = %q, want healthy; short-window-only exhausted credential must be guarded", got.ID)
	}
	alone := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	if _, err := alone.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{}, []*Auth{guarded}); err == nil {
		t.Fatal("Pick() with only short-window-exhausted credential succeeded, want error")
	}
}

func TestQuotaAwareStaleTelemetryDoesNotManufactureHeadroom(t *testing.T) {
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	stale := quotaTestAuth("a-stale", 0)
	stale.Quota.ObservedAt = time.Now().Add(-2 * time.Hour)
	fresh := quotaTestAuth("b-fresh", 50)
	if got := pickQuota(t, selector, stale, fresh); got.ID != fresh.ID {
		t.Fatalf("Pick() = %q, want fresh; stale 0%%-used snapshot must not manufacture headroom", got.ID)
	}

	// Bounded fallback: with no fresh candidate at all, unknown telemetry is
	// round-robined so a cold pool can bootstrap fresh signals.
	fallback := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	otherStale := quotaTestAuth("b-stale", 0)
	otherStale.Quota.ObservedAt = time.Now().Add(-2 * time.Hour)
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		seen[pickQuota(t, fallback, stale, otherStale).ID] = true
	}
	if len(seen) != 2 {
		t.Fatalf("unknown-telemetry fallback picked %v, want both credentials over 2 picks", seen)
	}
}

func TestQuotaAwareStaleExhaustedWithFutureResetStaysExhausted(t *testing.T) {
	now := time.Now()
	auth := quotaTestAuth("a-stale-exhausted", 100)
	auth.Quota.ObservedAt = now.Add(-2 * time.Hour)
	auth.Quota.Signals["X-Codex-Secondary-Reset-At"] = fmt.Sprint(now.Add(46 * time.Hour).Unix())
	eval := evaluateQuota(auth, now, QuotaAwarePolicy{}.normalizedQuotaAwarePolicy())
	if eval.Class != quotaClassExhausted {
		t.Fatalf("evaluateQuota() class = %v, want exhausted for stale 100%% snapshot whose reset is still future (%+v)", eval.Class, eval)
	}
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	if _, err := selector.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{}, []*Auth{auth}); err == nil {
		t.Fatal("Pick() with only stale weekly-exhausted (future reset) credential succeeded, want error")
	}
}

func TestQuotaAwareResetPassedSnapshotBecomesUnknownNotExhausted(t *testing.T) {
	now := time.Now()
	auth := quotaTestAuth("a-reset", 100)
	auth.Quota.ObservedAt = now.Add(-time.Hour)
	auth.Quota.Signals["X-Codex-Secondary-Reset-At"] = fmt.Sprint(now.Add(-time.Minute).Unix())
	eval := evaluateQuota(auth, now, QuotaAwarePolicy{}.normalizedQuotaAwarePolicy())
	if eval.Class == quotaClassExhausted {
		t.Fatalf("evaluateQuota() class = exhausted after weekly reset passed; want unknown/recoverable (%+v)", eval)
	}
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	if got := pickQuota(t, selector, auth); got.ID != auth.ID {
		t.Fatalf("Pick() = %q, want reset credential eligible via bounded fallback", got.ID)
	}
}

func TestQuotaAwareHysteresisAvoidsOscillation(t *testing.T) {
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0.02}}
	a := quotaTestAuth("a", 10)
	b := quotaTestAuth("b", 12)
	if got := pickQuota(t, selector, a, b); got.ID != a.ID {
		t.Fatalf("first Pick() = %q, want a", got.ID)
	}
	// b now leads by only 0.01 remaining fraction: within hysteresis, stay on a.
	setWeeklyUsed(a, 10)
	setWeeklyUsed(b, 9)
	if got := pickQuota(t, selector, a, b); got.ID != a.ID {
		t.Fatalf("Pick() within hysteresis = %q, want incumbent a", got.ID)
	}
	// b leads by 0.05: beyond hysteresis, switch.
	setWeeklyUsed(b, 5)
	if got := pickQuota(t, selector, a, b); got.ID != b.ID {
		t.Fatalf("Pick() beyond hysteresis = %q, want challenger b", got.ID)
	}
}

func TestQuotaAwareCreditsPacedByGreatestBalance(t *testing.T) {
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	small := quotaTestAuth("a-small-balance", 100)
	small.Attributes = map[string]string{AttributeCredits: CreditsKindFree}
	small.Quota.Signals["X-Codex-Credits-Has-Credits"] = "true"
	small.Quota.Signals["X-Codex-Credits-Balance"] = "100"
	large := quotaTestAuth("b-large-balance", 100)
	large.Attributes = map[string]string{AttributeCredits: CreditsKindFree}
	large.Quota.Signals["X-Codex-Credits-Has-Credits"] = "true"
	large.Quota.Signals["X-Codex-Credits-Balance"] = "900"
	if got := pickQuota(t, selector, small, large); got.ID != large.ID {
		t.Fatalf("Pick() = %q, want greatest credit balance first (paced drain)", got.ID)
	}
}

func TestQuotaAwareAddRemoveCandidates(t *testing.T) {
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	a := quotaTestAuth("a", 20)
	b := quotaTestAuth("b", 40)
	if got := pickQuota(t, selector, a, b); got.ID != a.ID {
		t.Fatalf("Pick() = %q, want a", got.ID)
	}
	// Removed candidate is never picked; the survivor keeps serving.
	if got := pickQuota(t, selector, b); got.ID != b.ID {
		t.Fatalf("Pick() after removal = %q, want b", got.ID)
	}
	// A newly added candidate with the greatest remaining fraction joins at once.
	c := quotaTestAuth("c", 5)
	if got := pickQuota(t, selector, b, c); got.ID != c.ID {
		t.Fatalf("Pick() after addition = %q, want c", got.ID)
	}
}

func TestValidateAuthCredits(t *testing.T) {
	if err := ValidateAuthCredits(&Auth{Metadata: map[string]any{AttributeCredits: "bogus"}}); err == nil {
		t.Fatal("ValidateAuthCredits(bogus) = nil, want error")
	}
	if err := ValidateAuthCredits(&Auth{Metadata: map[string]any{AttributeCredits: CreditsKindFree}}); err != nil {
		t.Fatalf("ValidateAuthCredits(free) = %v, want nil", err)
	}
	if err := ValidateAuthCredits(&Auth{Attributes: map[string]string{AttributeCredits: CreditsKindPaid}}); err != nil {
		t.Fatalf("ValidateAuthCredits(paid attribute) = %v, want nil", err)
	}
}

func TestQuotaAwarePassiveProbeRefreshesStaleCredential(t *testing.T) {
	// Only the picked credential receives a fresh snapshot, mirroring the
	// production MarkResult path. The stale idle credential must still get
	// bounded probe picks so it can refresh instead of starving forever.
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	busy := quotaTestAuth("a-busy", 10)
	idle := quotaTestAuth("b-idle", 0)
	idle.Quota.ObservedAt = time.Now().Add(-20 * time.Minute)
	used := map[string]float64{busy.ID: 10, idle.ID: 0}
	counts := map[string]int{}
	for i := 0; i < 100; i++ {
		got := pickQuota(t, selector, busy, idle)
		counts[got.ID]++
		used[got.ID]++
		setWeeklyUsed(got, used[got.ID])
	}
	if counts[idle.ID] == 0 {
		t.Fatalf("stale idle credential never probed (counts=%v)", counts)
	}
	if counts[busy.ID] == 100 {
		t.Fatalf("pool collapsed onto busy credential (counts=%v)", counts)
	}
}

func TestQuotaAwareExhaustedTopPriorityTierFallsThrough(t *testing.T) {
	exhausted := quotaTestAuth("a-hi-exhausted", 100)
	exhausted.Attributes = map[string]string{"priority": "10"}
	healthy := quotaTestAuth("b-lo-healthy", 10)
	healthy.Attributes = map[string]string{"priority": "0"}

	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	if got := pickQuota(t, selector, exhausted, healthy); got.ID != healthy.ID {
		t.Fatalf("selector Pick() = %q, want lower-tier healthy credential", got.ID)
	}

	scheduler := newSchedulerForTest(
		&QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}},
		quotaTestAuthWithPriority("a-hi-exhausted", 100, "10"),
		quotaTestAuthWithPriority("b-lo-healthy", 10, "0"),
	)
	got, errPick := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("scheduler pickSingle() error = %v, want lower-tier fall-through", errPick)
	}
	if got == nil || got.ID != "b-lo-healthy" {
		t.Fatalf("scheduler pickSingle() = %v, want b-lo-healthy", got)
	}
}

func quotaTestAuthWithPriority(id string, weeklyUsed float64, priority string) *Auth {
	auth := quotaTestAuth(id, weeklyUsed)
	auth.Attributes = map[string]string{"priority": priority}
	return auth
}

func TestQuotaAwareAffinityReleasesExhaustedBoundCredential(t *testing.T) {
	affinity := NewSessionAffinitySelector(&QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}})
	bound := quotaTestAuth("a-bound", 10)
	other := quotaTestAuth("b-other", 50)
	opts := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Id": []string{"quota-affinity-session"}}}

	got, err := affinity.Pick(context.Background(), "codex", "gpt-test", opts, []*Auth{bound, other})
	if err != nil || got == nil || got.ID != bound.ID {
		t.Fatalf("first Pick() = %v, %v; want bound credential a-bound", got, err)
	}

	// The bound credential goes weekly-exhausted onto a paid credits pool
	// that must not be spent; the session must move, not keep spending it.
	bound.Attributes = map[string]string{AttributeCredits: CreditsKindPaid}
	bound.Quota.Signals["X-Codex-Credits-Has-Credits"] = "true"
	bound.Quota.Signals["X-Codex-Credits-Balance"] = "500"
	setWeeklyUsed(bound, 100)
	for i := 0; i < 3; i++ {
		got, err = affinity.Pick(context.Background(), "codex", "gpt-test", opts, []*Auth{bound, other})
		if err != nil || got == nil || got.ID != other.ID {
			t.Fatalf("Pick() #%d after exhaustion = %v, %v; want reselected b-other", i, got, err)
		}
	}
}

func TestQuotaAwareStaleFreeCreditsServeAfterPlanExhaustion(t *testing.T) {
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	onCredits := quotaTestAuth("a-credits", 100)
	onCredits.Attributes = map[string]string{AttributeCredits: CreditsKindFree}
	onCredits.Quota.Signals["X-Codex-Credits-Has-Credits"] = "true"
	onCredits.Quota.Signals["X-Codex-Credits-Balance"] = "1000"
	// Free-credit credentials idle while plan quota lasts, so by the time
	// plan quota runs out their snapshot is older than stale-after.
	onCredits.Quota.ObservedAt = time.Now().Add(-time.Hour)
	exhaustedPlan := quotaTestAuth("b-plan", 100)
	if got := pickQuota(t, selector, onCredits, exhaustedPlan); got.ID != onCredits.ID {
		t.Fatalf("Pick() = %q, want stale free-credit credential probed into service", got.ID)
	}

	// The paid twin stays excluded while stale: a probe could spend money.
	paid := quotaTestAuth("c-paid", 100)
	paid.Attributes = map[string]string{AttributeCredits: CreditsKindPaid}
	paid.Quota.Signals["X-Codex-Credits-Has-Credits"] = "true"
	paid.Quota.Signals["X-Codex-Credits-Balance"] = "1000"
	paid.Quota.ObservedAt = time.Now().Add(-time.Hour)
	paidSelector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	if _, err := paidSelector.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{}, []*Auth{paid, exhaustedPlan}); err == nil {
		t.Fatal("Pick() with stale paid-credit credential succeeded, want error")
	}
}

func claudeQuotaTestAuth(id string, weeklyUtilization float64) *Auth {
	now := time.Now()
	return &Auth{
		ID:       id,
		Provider: "claude",
		Status:   StatusActive,
		Quota: QuotaState{
			ObservedAt: now,
			Signals: map[string]string{
				"Anthropic-Ratelimit-Unified-5h-Status":      "allowed",
				"Anthropic-Ratelimit-Unified-5h-Utilization": "0.1",
				"Anthropic-Ratelimit-Unified-5h-Reset":       fmt.Sprint(now.Add(2 * time.Hour).Unix()),
				"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
				"Anthropic-Ratelimit-Unified-7d-Utilization": fmt.Sprint(weeklyUtilization),
				"Anthropic-Ratelimit-Unified-7d-Reset":       fmt.Sprint(now.Add(72 * time.Hour).Unix()),
			},
		},
	}
}

func pickClaudeQuota(t *testing.T, selector *QuotaAwareSelector, auths ...*Auth) *Auth {
	t.Helper()
	got, err := selector.Pick(context.Background(), "claude", "claude-test", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil {
		t.Fatal("Pick() auth = nil")
	}
	return got
}

func TestQuotaAwareClaudeWeeklyUtilization(t *testing.T) {
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	nearlyFull := claudeQuotaTestAuth("a-nearly-full", 0.95)
	mostlyFree := claudeQuotaTestAuth("b-mostly-free", 0.05)
	if got := pickClaudeQuota(t, selector, nearlyFull, mostlyFree); got.ID != mostlyFree.ID {
		t.Fatalf("Pick() = %q, want credential with greatest remaining 7d fraction", got.ID)
	}
}

func TestQuotaAwareClaudeFiveHourRejectedIsGuarded(t *testing.T) {
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	guarded := claudeQuotaTestAuth("a-5h-rejected", 0.05)
	guarded.Quota.Signals["Anthropic-Ratelimit-Unified-5h-Status"] = "rejected"
	healthy := claudeQuotaTestAuth("b-healthy", 0.5)
	if got := pickClaudeQuota(t, selector, guarded, healthy); got.ID != healthy.ID {
		t.Fatalf("Pick() = %q, want healthy; 5h-rejected Claude credential must be guarded", got.ID)
	}
	alone := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	if _, err := alone.Pick(context.Background(), "claude", "claude-test", cliproxyexecutor.Options{}, []*Auth{guarded}); err == nil {
		t.Fatal("Pick() with only 5h-rejected Claude credential succeeded, want error")
	}
}

func TestQuotaAwareClaudeStaleRejectedWithFutureResetStaysExhausted(t *testing.T) {
	now := time.Now()
	rejected := claudeQuotaTestAuth("a-stale-rejected", 0.05)
	rejected.Quota.ObservedAt = now.Add(-time.Hour)
	rejected.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Status"] = "rejected"
	// Reset was refreshed to 72h out at construction; keep it in the future.
	eval := evaluateQuota(rejected, now, QuotaAwarePolicy{}.normalizedQuotaAwarePolicy())
	if eval.Class != quotaClassExhausted {
		t.Fatalf("evaluateQuota() class = %v, want exhausted for stale 7d-rejected snapshot with future reset (%+v)", eval.Class, eval)
	}
	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	if _, err := selector.Pick(context.Background(), "claude", "claude-test", cliproxyexecutor.Options{}, []*Auth{rejected}); err == nil {
		t.Fatal("Pick() with only stale 7d-rejected Claude credential succeeded, want error")
	}
}

func TestSchedulerPick_QuotaAware(t *testing.T) {
	scheduler := newSchedulerForTest(
		&QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}},
		quotaTestAuth("a-low-remaining", 80),
		quotaTestAuth("b-high-remaining", 20),
	)
	got, errPick := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("pickSingle() error = %v", errPick)
	}
	if got == nil || got.ID != "b-high-remaining" {
		t.Fatalf("pickSingle() = %v, want b-high-remaining", got)
	}
}

func quotaSchedulerAuth(id string, weeklyUsed float64, priority string, websockets bool) *Auth {
	auth := quotaTestAuth(id, weeklyUsed)
	auth.Attributes = map[string]string{"priority": priority}
	if websockets {
		auth.Attributes["websockets"] = "true"
	}
	return auth
}

func exhaustOnPaidCredits(auth *Auth) {
	auth.Attributes = map[string]string{AttributeCredits: CreditsKindPaid}
	auth.Quota.Signals["X-Codex-Credits-Has-Credits"] = "true"
	auth.Quota.Signals["X-Codex-Credits-Balance"] = "500"
	setWeeklyUsed(auth, 100)
}

func TestQuotaAwareAffinitySessionlessExhaustedTopTierFallsThrough(t *testing.T) {
	for _, prevalidated := range []bool{false, true} {
		affinity := NewSessionAffinitySelector(&QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}})
		exhausted := quotaTestAuthWithPriority("a-hi-exhausted", 100, "10")
		healthy := quotaTestAuthWithPriority("b-lo-healthy", 10, "0")
		ctx := context.Background()
		if prevalidated {
			ctx = context.WithValue(ctx, prevalidatedAuthCandidatesKey{}, true)
		}
		got, err := affinity.Pick(ctx, "codex", "gpt-test", cliproxyexecutor.Options{}, []*Auth{exhausted, healthy})
		if err != nil || got == nil || got.ID != healthy.ID {
			t.Fatalf("prevalidated=%v: sessionless Pick() = %v, %v; want lower-tier b-lo-healthy", prevalidated, got, err)
		}
	}
}

func TestQuotaAwareAffinityTwoTierSessionFallsThrough(t *testing.T) {
	affinity := NewSessionAffinitySelector(&QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}})
	exhausted := quotaTestAuthWithPriority("a-hi-exhausted", 100, "10")
	healthy := quotaTestAuthWithPriority("b-lo-healthy", 10, "0")
	opts := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Id": []string{"quota-two-tier-session"}}}
	got, err := affinity.Pick(context.Background(), "codex", "gpt-test", opts, []*Auth{exhausted, healthy})
	if err != nil || got == nil || got.ID != healthy.ID {
		t.Fatalf("Pick() = %v, %v; want lower-tier b-lo-healthy", got, err)
	}
}

func TestQuotaAwareAffinityFallbackKeyReleasesExhaustedBoundCredential(t *testing.T) {
	affinity := NewSessionAffinitySelector(&QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}})
	bound := quotaTestAuth("a-bound", 10)
	other := quotaTestAuth("b-other", 50)
	auths := []*Auth{bound, other}

	parentOpts := cliproxyexecutor.Options{
		Headers:  http.Header{"Session-Id": []string{"quota-parent-100"}, "Thread-Id": []string{"quota-parent-100"}},
		Metadata: map[string]any{},
	}
	got, err := affinity.Pick(context.Background(), "codex", "gpt-test", parentOpts, auths)
	if err != nil || got == nil || got.ID != bound.ID {
		t.Fatalf("parent Pick() = %v, %v; want a-bound", got, err)
	}

	exhaustOnPaidCredits(bound)
	forkOpts := cliproxyexecutor.Options{
		Headers: http.Header{
			"Session-Id":            []string{"quota-parent-100"},
			"Thread-Id":             []string{"quota-child-200"},
			"X-Codex-Turn-Metadata": []string{`{"session_id":"quota-parent-100","thread_id":"quota-child-200","forked_from_thread_id":"quota-parent-100"}`},
		},
		Metadata: map[string]any{},
	}
	got, err = affinity.Pick(context.Background(), "codex", "gpt-test", forkOpts, auths)
	if err != nil || got == nil || got.ID != other.ID {
		t.Fatalf("fork Pick() after bound exhaustion = %v, %v; want reselected b-other", got, err)
	}
}

func TestQuotaAwareAffinityLCPReleasesExhaustedBoundCredential(t *testing.T) {
	affinity := NewSessionAffinitySelector(&QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}})
	bound := quotaTestAuth("a-bound", 10)
	other := quotaTestAuth("b-other", 50)
	auths := []*Auth{bound, other}

	first := cliproxyexecutor.Options{
		SourceFormat:    sdktranslator.FormatOpenAI,
		OriginalRequest: []byte(`{"messages":[{"role":"system","content":"stable"},{"role":"user","content":"first"}]}`),
		Metadata:        map[string]any{cliproxyexecutor.CallerScopeMetadataKey: "caller-quota"},
	}
	got, err := affinity.Pick(context.Background(), "codex", "gpt-test", first, auths)
	if err != nil || got == nil || got.ID != bound.ID {
		t.Fatalf("first Pick() = %v, %v; want a-bound", got, err)
	}

	exhaustOnPaidCredits(bound)
	grown := cliproxyexecutor.Options{
		SourceFormat:    sdktranslator.FormatOpenAI,
		OriginalRequest: []byte(`{"messages":[{"role":"system","content":"stable"},{"role":"user","content":"first"},{"role":"assistant","content":"answer"},{"role":"user","content":"continue"}]}`),
		Metadata:        map[string]any{cliproxyexecutor.CallerScopeMetadataKey: "caller-quota"},
	}
	got, err = affinity.Pick(context.Background(), "codex", "gpt-test", grown, auths)
	if err != nil || got == nil || got.ID != other.ID {
		t.Fatalf("grown Pick() after bound exhaustion = %v, %v; want reselected b-other", got, err)
	}
}

func TestQuotaAwareSchedulerMixedExhaustedTopTierFallsThrough(t *testing.T) {
	codexHi := quotaTestAuthWithPriority("a-codex-hi-exhausted", 100, "10")
	claudeLo := claudeQuotaTestAuth("b-claude-lo-healthy", 0.1)
	claudeLo.Attributes = map[string]string{"priority": "0"}
	scheduler := newSchedulerForTest(
		&QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}},
		codexHi, claudeLo,
	)
	got, provider, errPick := scheduler.pickMixed(context.Background(), []string{"codex", "claude"}, "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("pickMixed() error = %v, want lower-tier fall-through", errPick)
	}
	if got == nil || got.ID != claudeLo.ID || provider != "claude" {
		t.Fatalf("pickMixed() = %v via %q, want b-claude-lo-healthy via claude", got, provider)
	}
}

func TestSchedulerPick_QuotaAwareWebsocketPrefersLowerTier(t *testing.T) {
	scheduler := newSchedulerForTest(
		&QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}},
		quotaSchedulerAuth("a-hi-http", 10, "10", false),
		quotaSchedulerAuth("b-lo-ws", 10, "0", true),
	)
	ctx := cliproxyexecutor.WithDownstreamWebsocket(context.Background())
	got, errPick := scheduler.pickSingle(ctx, "codex", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("pickSingle() error = %v", errPick)
	}
	if got == nil || got.ID != "b-lo-ws" {
		t.Fatalf("pickSingle() = %v, want websocket credential b-lo-ws from the lower tier", got)
	}
}

func TestSchedulerPick_QuotaAwareWebsocketTierFallsBackToHTTP(t *testing.T) {
	scheduler := newSchedulerForTest(
		&QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}},
		quotaSchedulerAuth("a-ws-exhausted", 100, "0", true),
		quotaSchedulerAuth("b-http-healthy", 10, "0", false),
	)
	ctx := cliproxyexecutor.WithDownstreamWebsocket(context.Background())
	got, errPick := scheduler.pickSingle(ctx, "codex", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("pickSingle() error = %v, want same-tier HTTP fallback", errPick)
	}
	if got == nil || got.ID != "b-http-healthy" {
		t.Fatalf("pickSingle() = %v, want b-http-healthy when the tier's websocket credential is quota-exhausted", got)
	}
}

func TestQuotaAwareStaleFiveHourExhaustedStaysExhausted(t *testing.T) {
	now := time.Now()

	codexGuarded := quotaTestAuth("a-codex-5h", 10)
	codexGuarded.Quota.Signals["X-Codex-Primary-Used-Percent"] = "100"
	codexGuarded.Quota.ObservedAt = now.Add(-20 * time.Minute)
	if eval := evaluateQuota(codexGuarded, now, QuotaAwarePolicy{}.normalizedQuotaAwarePolicy()); eval.Class != quotaClassExhausted {
		t.Fatalf("codex evaluateQuota() class = %v, want exhausted for stale 5h-exhausted snapshot with reset 2h out (%+v)", eval.Class, eval)
	}

	claudeGuarded := claudeQuotaTestAuth("b-claude-5h", 0.05)
	claudeGuarded.Quota.Signals["Anthropic-Ratelimit-Unified-5h-Status"] = "rejected"
	claudeGuarded.Quota.ObservedAt = now.Add(-20 * time.Minute)
	if eval := evaluateQuota(claudeGuarded, now, QuotaAwarePolicy{}.normalizedQuotaAwarePolicy()); eval.Class != quotaClassExhausted {
		t.Fatalf("claude evaluateQuota() class = %v, want exhausted for stale 5h-rejected snapshot with reset 2h out (%+v)", eval.Class, eval)
	}

	selector := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	healthy := quotaTestAuth("c-healthy", 50)
	if got := pickQuota(t, selector, codexGuarded, healthy); got.ID != healthy.ID {
		t.Fatalf("Pick() = %q, want healthy; stale 5h-exhausted credential must stay guarded until its reset", got.ID)
	}
	alone := &QuotaAwareSelector{Policy: QuotaAwarePolicy{Hysteresis: 0}}
	if _, err := alone.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{}, []*Auth{codexGuarded}); err == nil {
		t.Fatal("Pick() with only stale 5h-exhausted credential succeeded, want error")
	}
}
