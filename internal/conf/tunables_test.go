package conf

import (
	"strconv"
	"testing"
)

// The tunables half of tests/unit/hash.bats (tacctl 0.1.16), deferred by
// WP1.2 to this package: bcrypt.cost, password.min_length and
// secret.min_length as resolved when lib/conf.sh is sourced. internal/hash
// and internal/ui take the resolved values as parameters.

func tunablesOf(t *testing.T, content string) Tunables {
	t.Helper()
	c := tempConf(t)
	if content != "" {
		writeFile(t, c.Path, content)
		c.Reload()
	}
	return c.Tunables()
}

func TestBcryptCostDefaultIs12WhenFileMissing(t *testing.T) {
	if got := tempConf(t).Tunables().BcryptCost; got != 12 {
		t.Fatalf("got %d", got)
	}
}

func TestBcryptCostAcceptsValuesIn10To14FromOverrides(t *testing.T) {
	c := tempConf(t)
	for _, v := range []string{"11", "14"} {
		must(t, c.Set("bcrypt.cost", v))
		if got := Load(c.Path, DefaultBackends).Tunables().BcryptCost; strconv.Itoa(got) != v {
			t.Fatalf("%s: got %d", v, got)
		}
	}
}

func TestBcryptCostClampsOutOfRangeToDefault12(t *testing.T) {
	for _, content := range []string{"bcrypt:\n  cost: 8\n", "bcrypt:\n  cost: 99\n"} {
		if got := tunablesOf(t, content).BcryptCost; got != 12 {
			t.Fatalf("%q: got %d", content, got)
		}
	}
}

func TestBcryptCostNonNumericValueClampsToDefault(t *testing.T) {
	if got := tunablesOf(t, "bcrypt:\n  cost: hello\n").BcryptCost; got != 12 {
		t.Fatalf("got %d", got)
	}
}

func TestPasswordMinLengthDefault12ClampsTo8To64(t *testing.T) {
	if got := tempConf(t).Tunables().PasswordMinLength; got != 12 {
		t.Fatalf("default %d", got)
	}
	c := tempConf(t)
	for _, v := range []int{8, 64} {
		must(t, c.Set("password.min_length", strconv.Itoa(v)))
		if got := Load(c.Path, DefaultBackends).Tunables().PasswordMinLength; got != v {
			t.Fatalf("%d: got %d", v, got)
		}
	}
	for _, content := range []string{"password:\n  min_length: 7\n", "password:\n  min_length: 65\n"} {
		if got := tunablesOf(t, content).PasswordMinLength; got != 12 {
			t.Fatalf("%q: got %d", content, got)
		}
	}
}

func TestSecretMinLengthDefault16ClampsTo16To128(t *testing.T) {
	if got := tempConf(t).Tunables().SecretMinLength; got != 16 {
		t.Fatalf("default %d", got)
	}
	c := tempConf(t)
	for _, v := range []int{16, 128} {
		must(t, c.Set("secret.min_length", strconv.Itoa(v)))
		if got := Load(c.Path, DefaultBackends).Tunables().SecretMinLength; got != v {
			t.Fatalf("%d: got %d", v, got)
		}
	}
	for _, content := range []string{"secret:\n  min_length: 15\n", "secret:\n  min_length: 129\n"} {
		if got := tunablesOf(t, content).SecretMinLength; got != 16 {
			t.Fatalf("%q: got %d", content, got)
		}
	}
}

func TestPasswordMaxAgeDaysClamp(t *testing.T) {
	for content, want := range map[string]int{
		"":                                  90,
		"password:\n  max_age_days: 0\n":    90,
		"password:\n  max_age_days: 5000\n": 5000,
		"password:\n  max_age_days: 1.5\n":  90,
		"password:\n  max_age_days: '30'\n": 30,
		"password: [1]\n":                   90,
	} {
		if got := tunablesOf(t, content).PasswordMaxAgeDays; got != want {
			t.Errorf("%q: got %d, want %d", content, got, want)
		}
	}
}
