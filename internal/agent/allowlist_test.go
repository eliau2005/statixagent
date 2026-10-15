package agent

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/telegram"
)

// emittedDataPrefixes scans this package's non-test sources for every
// `Data:` value a button is built with and returns what each one starts
// with: a literal or constant whole, the literal head of a concatenation,
// or the literal first argument of a builder such as fmt.Sprintf("pa:%d")
// or watchIndexData("sa:", …). Values with no literal head are returned
// as source text in dynamic, for the caller to cover another way.
func emittedDataPrefixes(t *testing.T) (prefixes, dynamic []string) {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var parsed []*ast.File
	consts := map[string]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, f)
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, v := range vs.Values {
					if s, ok := stringLit(v); ok {
						consts[vs.Names[i].Name] = s
					}
				}
			}
		}
	}
	var head func(ast.Expr) (string, bool)
	head = func(e ast.Expr) (string, bool) {
		switch e := e.(type) {
		case *ast.BasicLit:
			return stringLit(e)
		case *ast.Ident:
			s, ok := consts[e.Name]
			return s, ok
		case *ast.BinaryExpr:
			if e.Op == token.ADD {
				return head(e.X)
			}
		case *ast.CallExpr:
			if len(e.Args) > 0 {
				if s, ok := stringLit(e.Args[0]); ok {
					s, _, _ = strings.Cut(s, "%")
					return s, true
				}
			}
		}
		return "", false
	}
	for _, f := range parsed {
		ast.Inspect(f, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Data" {
				return true
			}
			if s, ok := head(kv.Value); ok {
				prefixes = append(prefixes, s)
			} else {
				dynamic = append(dynamic, types.ExprString(kv.Value))
			}
			return true
		})
	}
	return prefixes, dynamic
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// pressRoutes presses data on a fresh agent and reports whether it was
// routed, i.e. answered with anything but the outdated toast.
func pressRoutes(t *testing.T, data string) bool {
	t.Helper()
	send := &fakeSender{}
	a := testAgent(send)
	a.src.Runner = failingUFW{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // ends a Live session started by the press
	a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 5, Data: data})
	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.answered) != 1 {
		t.Errorf("%q: answered %v, want exactly once", data, send.answered)
		return false
	}
	return !strings.HasPrefix(send.answered[0], "c1:"+outdatedToast)
}

// TestEmittedCallbackDataRoutes is the inventory behind the callback
// allowlist: every Data value the code builds a button with, and every
// button of the keyboards built at run time, must still reach a handler.
func TestEmittedCallbackDataRoutes(t *testing.T) {
	prefixes, dynamic := emittedDataPrefixes(t)
	if len(prefixes) < 40 {
		t.Fatalf("found only %d Data literals; is the scan broken?", len(prefixes))
	}
	slices.Sort(prefixes)
	for _, data := range slices.Compact(prefixes) {
		if !pressRoutes(t, data) {
			t.Errorf("emitted callback data %q does not route", data)
		}
	}

	// Values with no literal head come from these builders; each is
	// covered below by pressing the keyboards they build.
	covered := map[string]bool{
		"b.cmd":                     true, // navKeyboard
		"a.snoozeCallbackData(key)": true, // alertKeyboard
		"data":                      true, // trustButton
	}
	for _, d := range dynamic {
		if !covered[d] {
			t.Errorf("Data: %s has no literal head; cover its keyboard in this test", d)
		}
	}
	a := testAgent(&fakeSender{})
	kbs := []telegram.Keyboard{
		updateKeyboard(), updateConfirmKeyboard(), clearConfirmKeyboard(),
		{a.trustButton("203.0.113.7")},
	}
	for v := range navViews {
		kbs = append(kbs, navKeyboard(v))
	}
	for _, key := range []string{"ssh-login:x", "cpu", "mem", "disk:/", "temp", "ssl:x", "docker:x", "battery", "other",
		"a-very-long-alert-key-that-needs-the-hashed-snooze-form-to-fit-in-64-bytes"} {
		kbs = append(kbs, a.alertKeyboard(key))
	}
	for _, kb := range kbs {
		for _, row := range kb {
			for _, b := range row {
				if b.Data == "" {
					t.Errorf("button %q has no data", b.Text)
					continue
				}
				if !pressRoutes(t, b.Data) {
					t.Errorf("button %q data %q does not route", b.Text, b.Data)
				}
			}
		}
	}
}

// TestForgedCallbackRejected: data no button emits never reaches the
// router, even when it names a real command. A forged clear_chat is
// refused without acting.
func TestForgedCallbackRejected(t *testing.T) {
	for _, data := range []string{
		"clear_chat", "update", "start", "help", "ping", "trust",
		"untrust", "services_add", "ports_remove", "procs_add", "trusted", "no_such_action",
	} {
		t.Run(data, func(t *testing.T) {
			send := &fakeSender{}
			a := testAgent(send)
			applied := false
			a.src.UpdateCheck = func(context.Context) (string, bool, error) { return "v2", true, nil }
			a.src.UpdateApply = func(context.Context) error { applied = true; return nil }
			ran := countHandler(a, data)
			a.handleCallback(context.Background(), &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 5, Data: data})
			send.mu.Lock()
			defer send.mu.Unlock()
			if *ran != 0 || applied || len(send.deleted) != 0 || len(send.edits) != 0 || len(send.sent) != 0 {
				t.Errorf("forged %q acted: ran=%d applied=%v deleted=%d edits=%d sent=%v",
					data, *ran, applied, len(send.deleted), len(send.edits), send.sent)
			}
			if !slices.Equal(send.answered, []string{"c1:" + outdatedToast}) {
				t.Errorf("answered = %v, want the outdated toast once", send.answered)
			}
		})
	}
}

// TestLegacyUpdateConfirmReprompts: the Install button of an older
// version asks again with a fresh Yes and never installs by itself.
func TestLegacyUpdateConfirmReprompts(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	applied := false
	a.src.UpdateCheck = func(context.Context) (string, bool, error) { return "v2", true, nil }
	a.src.UpdateApply = func(context.Context) error { applied = true; return nil }
	a.handleCallback(context.Background(), &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 5, Data: "update_confirm"})
	send.mu.Lock()
	defer send.mu.Unlock()
	if applied {
		t.Fatal("legacy update_confirm installed the update")
	}
	if len(send.edits) != 1 || !strings.Contains(send.edits[0].html, "Install the update?") || len(send.edits[0].kb) == 0 || send.edits[0].kb[0][0].Data != cbUpdateYes {
		t.Fatalf("edits = %v, want the confirm prompt", send.edits)
	}
	if !slices.Equal(send.answered, []string{"c1:Please confirm again"}) {
		t.Errorf("answered = %v, want one re-confirm toast", send.answered)
	}
}

// TestConfirmYesReauthorizes: the Yes buttons are not views, so in a group
// with admins only an admin may press them, and a foreign chat is ignored.
func TestConfirmYesReauthorizes(t *testing.T) {
	for _, data := range []string{cbUpdateYes, cbClearYes} {
		t.Run(data, func(t *testing.T) {
			ctx := context.Background()
			send := &fakeSender{}
			a, _ := authAgent(t, send, -100, 7)
			applied := 0
			a.src.UpdateCheck = func(context.Context) (string, bool, error) { return "v2", true, nil }
			a.src.UpdateApply = func(context.Context) error { applied++; return nil }
			acted := func() bool {
				send.mu.Lock()
				defer send.mu.Unlock()
				return applied > 0 || len(send.deleted) > 0
			}

			a.handleCallback(ctx, &telegram.Callback{ID: "foreign", ChatID: 666, ChatType: "group", FromID: 7, MessageID: 5, Data: data})
			a.handleCallback(ctx, &telegram.Callback{ID: "member", ChatID: -100, ChatType: "supergroup", FromID: 5, MessageID: 5, Data: data})
			if acted() {
				t.Fatal("Yes acted for a foreign chat or a non-admin")
			}
			send.mu.Lock()
			answered := slices.Clone(send.answered)
			send.mu.Unlock()
			if !slices.Equal(answered, []string{"member:" + adminOnlyToast}) {
				t.Errorf("answered = %v, want only the non-admin refused", answered)
			}

			a.handleCallback(ctx, &telegram.Callback{ID: "admin", ChatID: -100, ChatType: "supergroup", FromID: 7, MessageID: 5, Data: data})
			if !acted() {
				t.Error("Yes from an admin did not act")
			}
		})
	}
}

// TestCommandMenuScopedToChat: the menu is set for the allowed chat first
// and the public default menu is deleted after; /update_confirm is no
// longer offered.
func TestCommandMenuScopedToChat(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.registerCommands(context.Background())
	if want := []string{"set:chat:42", "delete:default:0"}; !slices.Equal(send.scopes, want) {
		t.Errorf("scopes = %v, want %v", send.scopes, want)
	}
	for _, c := range send.cmds {
		if c.Command == "update_confirm" {
			t.Error("/update_confirm must not be in the command menu")
		}
	}
	if len(send.cmds) == 0 {
		t.Error("no commands registered")
	}
}

// TestCommandMenuSetFailureKeepsDefault: when the chat menu cannot be set,
// the default one is left alone so the owner still has a menu.
func TestCommandMenuSetFailureKeepsDefault(t *testing.T) {
	send := &fakeSender{setCmdsErr: hostileErr}
	a := testAgent(send)
	a.registerCommands(context.Background())
	if want := []string{"set:chat:42"}; !slices.Equal(send.scopes, want) {
		t.Errorf("scopes = %v, want %v", send.scopes, want)
	}
}
