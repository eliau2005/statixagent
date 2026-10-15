package tgui

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	// The examples of the design doc's length budget (§4.2).
	cases := []struct {
		call Call
		data string
	}{
		{Call{Act: "v", Args: []string{"cpu"}}, "~1v|cpu"},
		{Call{Act: "l", Args: []string{"un", "f", "2"}}, "~1l|un|f|2"},
		{Call{Act: "th", Args: []string{"cpu", "85"}}, "~1th|cpu|85"},
		{Call{Act: "fr", Args: []string{"9f3c1a", "4"}, From: "fl"}, "~1fr|9f3c1a|4^fl"},
		{Call{Act: "n", Args: []string{"AbCdEfGhIjKl"}}, "~1n|AbCdEfGhIjKl"},
		{Call{Act: "y", Args: []string{"k7q2", "AbCdEfGhIjKl"}}, "~1y|k7q2|AbCdEfGhIjKl"},
		{Call{Act: "d", Args: []string{"c", "3f2a9b7c1d0e"}, From: "dk"}, "~1d|c|3f2a9b7c1d0e^dk"},
		{Call{Act: "d", Args: []string{"u", "9f3c1a0b2d4e6f81"}, From: "un"}, "~1d|u|9f3c1a0b2d4e6f81^un"},
		{Call{Act: "tk", Args: []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}, From: "al"}, "~1tk|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff^al"},
		{Call{Act: "ut", Args: []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"}, From: "tr"}, "~1ut|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128^tr"},
		{Call{Act: "abc"}, "~1abc"},
		{Call{Act: "x", Args: []string{"A-z.0_:/*"}}, "~1x|A-z.0_:/*"},
	}
	for _, tc := range cases {
		data, err := Encode(tc.call)
		if err != nil || data != tc.data {
			t.Errorf("Encode(%+v) = %q, %v; want %q", tc.call, data, err, tc.data)
			continue
		}
		got, err := Decode(data)
		if err != nil || !reflect.DeepEqual(got, tc.call) {
			t.Errorf("Decode(%q) = %+v, %v; want %+v", data, got, err, tc.call)
		}
	}
}

func TestEncodeRejects(t *testing.T) {
	long := strings.Repeat("a", MaxData)
	cases := []struct {
		name string
		call Call
		want error
	}{
		{"empty act", Call{}, ErrMalformed},
		{"long act", Call{Act: "view"}, ErrMalformed},
		{"upper act", Call{Act: "V"}, ErrMalformed},
		{"empty arg", Call{Act: "v", Args: []string{""}}, ErrMalformed},
		{"pipe in arg", Call{Act: "v", Args: []string{"a|b"}}, ErrMalformed},
		{"caret in arg", Call{Act: "v", Args: []string{"a^b"}}, ErrMalformed},
		{"space in arg", Call{Act: "v", Args: []string{"a b"}}, ErrMalformed},
		{"non-ASCII arg", Call{Act: "v", Args: []string{"café"}}, ErrMalformed},
		{"HTML arg", Call{Act: "v", Args: []string{"<b>"}}, ErrMalformed},
		{"long from", Call{Act: "v", From: "home"}, ErrMalformed},
		{"digit from", Call{Act: "v", From: "a1"}, ErrMalformed},
		{"over 64 bytes", Call{Act: "v", Args: []string{long}}, ErrTooLong},
	}
	for _, tc := range cases {
		if data, err := Encode(tc.call); !errors.Is(err, tc.want) {
			t.Errorf("%s: Encode = %q, %v; want %v", tc.name, data, err, tc.want)
		}
	}
	// Exactly 64 bytes is still allowed.
	exact := Call{Act: "v", Args: []string{strings.Repeat("a", MaxData-len("~1v|"))}}
	if data, err := Encode(exact); err != nil || len(data) != MaxData {
		t.Errorf("64-byte call: %q, %v", data, err)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, data := range []string{
		"", "~", "~1", "~2v|cpu", "~0v", "1v|cpu", "status", "snz:d:cpu",
		"~1V", "~1view|cpu", "~1v|", "~1v||cpu", "~1v|cpu|", "~1v|cpu^", "~1v|cpu^^a",
		"~1v^a|cpu", "~1v|cpu^home", "~1v|cpu^A", "~1v|c pu", "~1v|<b>", "~1v|é",
		"~1v|cpu\n", "~1|cpu", "~1v|cpu^a^b",
		"~1v|" + strings.Repeat("a", MaxData),
	} {
		if c, err := Decode(data); err == nil {
			t.Errorf("Decode(%q) = %+v, want an error", data, c)
		}
	}
}

func TestDecodeErrorsDoNotQuoteData(t *testing.T) {
	_, err := Decode("~1v|<secret token>")
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("error must not echo forged data: %v", err)
	}
}

func TestIsCall(t *testing.T) {
	for data, want := range map[string]bool{
		"~1v|cpu": true, "~": true, "status": false, "snz:d:cpu": false, "": false,
	} {
		if IsCall(data) != want {
			t.Errorf("IsCall(%q) = %v", data, !want)
		}
	}
}

// FuzzDecode checks that Decode never panics and that whatever it accepts
// is canonical: it encodes back to exactly the same data.
func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		"~1v|cpu", "~1fr|9f3c1a|4^fl", "~1ut|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128^tr",
		"~1v", "~1v|", "~1v|a^", "status", "~2v", "~1v|a|b|c^xyz", "",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		c, err := Decode(data)
		if err != nil {
			return
		}
		got, err := Encode(c)
		if err != nil {
			t.Fatalf("Decode(%q) = %+v, which does not encode: %v", data, c, err)
		}
		if got != data {
			t.Fatalf("Decode(%q) re-encodes as %q", data, got)
		}
	})
}
