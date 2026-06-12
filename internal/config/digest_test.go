package config

import (
	"strings"
	"testing"
)

func TestDigestDefaults(t *testing.T) {
	c := Default()
	if !c.Digest.Enabled || c.Digest.Hour != 9 {
		t.Errorf("digest defaults: %+v, want enabled at hour 9", c.Digest)
	}
}

func TestDigestHourValidated(t *testing.T) {
	c := Default()
	c.Telegram.Token = "t"
	c.Telegram.ChatID = 1
	for _, hour := range []int{-1, 24} {
		c.Digest.Hour = hour
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "digest.hour") {
			t.Errorf("hour %d: want digest.hour error, got %v", hour, err)
		}
	}
	c.Digest.Hour = 23
	if err := c.Validate(); err != nil {
		t.Errorf("hour 23 must be valid: %v", err)
	}
}
