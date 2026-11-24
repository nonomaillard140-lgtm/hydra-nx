package score

import "testing"

func TestPriority(t *testing.T) {
	result := Score("env_exposure", "smtp", 5)
	if result.Points < 80 || result.Priority > 100 || result.Priority <= result.Points {
		t.Fatalf("score incohérent: %+v", result)
	}
}
