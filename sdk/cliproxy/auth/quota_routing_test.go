package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
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
