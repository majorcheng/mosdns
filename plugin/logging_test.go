package plugin

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/pkg/server_handler"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestRequestLogging(t *testing.T) {
	// A real UDP test upstream with local records; no public DNS is contacted.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	upstream := &dns.Server{
		PacketConn:        conn,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			r := new(dns.Msg)
			r.SetReply(q)
			question := q.Question[0]
			hdr := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 1}
			switch question.Qtype {
			case dns.TypeA:
				if question.Name != "v6-only.test." {
					r.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4(192, 0, 2, 1)}}
				}
			case dns.TypeAAAA:
				r.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::1")}}
			}
			if question.Name == "large.test." {
				for i := 0; i < 80; i++ {
					r.Answer = append(r.Answer, &dns.A{Hdr: hdr, A: net.IPv4(192, 0, 2, byte(i+2))})
				}
			}
			if err := w.WriteMsg(r); err != nil {
				t.Error(err)
			}
		}),
	}
	upstreamDone := make(chan error, 1)
	go func() { upstreamDone <- upstream.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-upstreamDone:
		_ = conn.Close()
		t.Fatalf("start upstream: %v", err)
	}
	t.Cleanup(func() {
		if err := upstream.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-upstreamDone; err != nil {
			t.Error(err)
		}
	})

	seq := func(tag string, execs ...string) coremain.PluginConfig {
		rules := make(sequence.Args, 0, len(execs))
		for _, exec := range execs {
			rules = append(rules, sequence.RuleArgs{Exec: exec})
		}
		return coremain.PluginConfig{Tag: tag, Type: "sequence", Args: &rules}
	}

	for _, mode := range []string{"json", "console", "info"} {
		t.Run(mode, func(t *testing.T) {
			level := "debug"
			if mode == "info" {
				level = "info"
			}
			logFile := filepath.Join(t.TempDir(), "mosdns.log")
			m, err := coremain.NewMosdns(&coremain.Config{
				Log: mlog.LogConfig{Level: level, File: logFile, Production: mode == "json"},
				Plugins: []coremain.PluginConfig{
					{Tag: "up", Type: "forward", Args: map[string]any{"upstreams": []map[string]any{{"tag": "loopback", "addr": conn.LocalAddr().String()}}}},
					{Tag: "cache", Type: "cache", Args: map[string]any{"lazy_cache_ttl": 60}},
					seq("resolve", "$up", "return"),
					{Tag: "main", Type: "sequence", Args: &sequence.Args{
						{Exec: "query_summary"},
						{Matches: []string{"qtype 28"}, Exec: "reject"},
						{Exec: "$cache"},
						{Matches: []string{"has_resp"}, Exec: "accept"},
						{Exec: "jump resolve"},
						{Exec: "accept"},
					}},
					seq("empty", "return"),
					seq("slow", "sleep 1000"),
					seq("remote", "black_hole 192.0.2.2"),
					seq("local", "black_hole 192.0.2.3"),
					{Tag: "pc_remote", Type: "probe_choice", Args: map[string]any{"probe_exec": "empty", "remote_exec": "remote", "local_exec": "local", "probe_wait": 200}},
					{Tag: "pc_local", Type: "probe_choice", Args: map[string]any{"probe_exec": "slow", "remote_exec": "remote", "local_exec": "local", "probe_wait": 5}},
					{Tag: "race_probe", Type: "raceback", Args: map[string]any{"probe_exec": "pc_remote", "local_exec": "local", "probe_wait": 200, "timeout": 1000}},
					{Tag: "race_local", Type: "raceback", Args: map[string]any{"probe_exec": "empty", "local_exec": "local", "probe_wait": 5}},
					{Tag: "fb_primary", Type: "fallback", Args: map[string]any{"primary": "remote", "secondary": "local"}},
					{Tag: "fb_secondary", Type: "fallback", Args: map[string]any{"primary": "empty", "secondary": "local"}},
					{Tag: "fb_standby", Type: "fallback", Args: map[string]any{"primary": "empty", "secondary": "local", "always_standby": true}},
					seq("prefer", "query_summary", "prefer_ipv4", "$up"),
					seq("goto", "query_summary", "goto resolve", "reject"),
					seq("failed", "query_summary", "$local", "sleep 1000"),
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				m.CloseWithErr(nil)
				if err := m.GetSafeClose().WaitClosed(); err != nil {
					t.Error(err)
				}
			})
			readLog := func() string {
				t.Helper()
				b, err := os.ReadFile(logFile)
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			cases := []struct {
				name, entry, domain, event, key, value, answer string
				qtype                                          uint16
				rcode                                          int
			}{
				{name: "miss", entry: "main", domain: "cached.test.", event: "cache lookup", key: "result", value: "miss", answer: "192.0.2.1"},
				{name: "hit", entry: "main", domain: "cached.test.", event: "cache lookup", key: "result", value: "hit", answer: "192.0.2.1"},
				{name: "stale", entry: "main", domain: "cached.test.", event: "lazy cache refresh finished", answer: "192.0.2.1"},
				{name: "skip", entry: "main", event: "cache skipped", answer: "192.0.2.1"},
				{name: "pc_remote", entry: "pc_remote", event: "branch selected", key: "selected", value: "remote", answer: "192.0.2.2"},
				{name: "pc_local", entry: "pc_local", event: "branch selected", key: "selected", value: "local", answer: "192.0.2.3"},
				{name: "nested", entry: "race_probe", event: "branch selected", key: "selected", value: "probe", answer: "192.0.2.2"},
				{name: "race_local", entry: "race_local", event: "branch selected", key: "selected", value: "local", answer: "192.0.2.3"},
				{name: "fb_primary", entry: "fb_primary", event: "branch selected", key: "selected", value: "primary", answer: "192.0.2.2"},
				{name: "fb_secondary", entry: "fb_secondary", event: "branch selected", key: "selected", value: "secondary", answer: "192.0.2.3"},
				{name: "fb_standby", entry: "fb_standby", event: "branch selected", key: "selected", value: "secondary", answer: "192.0.2.3"},
				{name: "prefer_suppress", entry: "prefer", qtype: dns.TypeAAAA, event: "address preference decision", key: "result", value: "suppress"},
				{name: "prefer_pass", entry: "prefer", domain: "v6-only.test.", qtype: dns.TypeAAAA, event: "address preference decision", key: "result", value: "pass", answer: "2001:db8::1"},
				{name: "goto", entry: "goto", event: "rule executing", key: "exec", value: "goto resolve", answer: "192.0.2.1"},
				{name: "no_response", entry: "empty", rcode: dns.RcodeRefused, event: "response ready", key: "reason", value: "entry returned no response"},
				{name: "entry_error", entry: "failed", rcode: dns.RcodeServerFailure, event: "response ready", key: "reason", value: "entry failed"},
				{name: "truncated", entry: "resolve", domain: "large.test.", event: "response ready"},
				{name: "unknown_type", entry: "resolve", qtype: 65280, event: "response ready"},
			}
			if mode != "json" {
				cases = cases[:1]
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					if tc.name == "stale" {
						time.Sleep(1100 * time.Millisecond)
					}
					if tc.domain == "" {
						tc.domain = tc.name + ".test."
					}
					if tc.qtype == 0 {
						tc.qtype = dns.TypeA
					}
					q := new(dns.Msg)
					q.SetQuestion(tc.domain, tc.qtype)
					if tc.name == "skip" {
						q.Opcode = dns.OpcodeNotify
					}
					timeout := time.Second
					if tc.name == "entry_error" {
						timeout = 10 * time.Millisecond
					}
					h := server_handler.NewEntryHandler(server_handler.EntryHandlerOpts{
						Logger: m.Logger().Named("test_server"), Entry: sequence.ToExecutable(m.GetPlugin(tc.entry)), QueryTimeout: timeout,
					})
					offset := len(readLog())
					payload := h.Handle(context.Background(), q, server.QueryMeta{ClientAddr: netip.MustParseAddr("127.0.0.1"), FromUDP: true}, pool.PackBuffer)
					if payload == nil {
						t.Fatal("request produced no payload")
					}
					defer pool.ReleaseBuf(payload)
					r := new(dns.Msg)
					if err := r.Unpack(*payload); err != nil {
						t.Fatal(err)
					}
					if r.Id != q.Id || r.Rcode != tc.rcode || r.Question[0] != q.Question[0] {
						t.Fatalf("unexpected DNS response: %s", r)
					}
					if tc.answer != "" {
						if len(r.Answer) != 1 || !strings.HasSuffix(r.Answer[0].String(), tc.answer) {
							t.Fatalf("answer = %v, want %s", r.Answer, tc.answer)
						}
					} else if tc.name != "truncated" && len(r.Answer) != 0 {
						t.Fatalf("unexpected answer: %v", r.Answer)
					}
					if mode != "json" {
						text := readLog()[offset:]
						for _, want := range []string{"\tINFO\t", "query summary", `"qtype_name": "A"`, `"qclass_name": "IN"`, `"rcode_name": "NOERROR"`} {
							if !strings.Contains(text, want) {
								t.Fatalf("console log missing %q:\n%s", want, text)
							}
						}
						if (mode == "console") != strings.Contains(text, "\tDEBUG\t") {
							t.Fatalf("unexpected debug output for %s:\n%s", mode, text)
						}
						if mode == "console" {
							t.Logf("actual console request log:\n%s", text)
						}
						return
					}

					var records []map[string]any
					var decision map[string]any
					deadline := time.Now().Add(time.Second)
					for {
						records = nil
						var uqid any
						for _, line := range strings.Split(strings.TrimSpace(readLog()[offset:]), "\n") {
							var record map[string]any
							if err := json.Unmarshal([]byte(line), &record); err != nil {
								t.Fatal(err)
							}
							if record["msg"] == "query received" {
								uqid = record["query"].(map[string]any)["uqid"]
							}
							records = append(records, record)
						}
						if uqid == nil {
							t.Fatal("query received has no request ID")
						}
						filtered := records[:0]
						for _, record := range records {
							id := record["uqid"]
							if query, ok := record["query"].(map[string]any); ok {
								id = query["uqid"]
							}
							if id == uqid {
								filtered = append(filtered, record)
								if record["msg"] == tc.event && (tc.key == "" || record[tc.key] == tc.value) {
									decision = record
								}
							}
						}
						records = filtered
						if decision != nil {
							break
						}
						if time.Now().After(deadline) {
							t.Fatalf("missing correlated event %s %s=%s:\n%s", tc.event, tc.key, tc.value, readLog()[offset:])
						}
						time.Sleep(time.Millisecond)
					}
					if tc.event == "branch selected" {
						if reason, ok := decision["reason"].(string); !ok || reason == "" {
							t.Fatal("branch selection has no reason")
						}
						if tc.name == "pc_local" {
							b, err := json.Marshal(decision)
							if err != nil {
								t.Fatal(err)
							}
							t.Logf("actual branch decision: %s", b)
						}
					}
					seen := make(map[string]bool)
					branches := make(map[string]bool)
					for _, record := range records {
						msg := record["msg"].(string)
						seen[msg] = true
						if query, ok := record["query"].(map[string]any); ok {
							if branch, ok := query["branch"].(string); ok {
								branches[branch] = true
							}
							if msg == "response ready" && (query["qtype"] != float64(tc.qtype) || query["qtype_name"] != dns.Type(tc.qtype).String() || query["branch"] != nil) {
								t.Fatalf("wrong final request metadata: %v", query)
							}
						}
						if msg == "response ready" {
							response := record["response"].(map[string]any)
							if response["rcode"] != float64(r.Rcode) || response["rcode_name"] != dns.RcodeToString[r.Rcode] || response["answers"] != float64(len(r.Answer)) || record["truncated"] != r.Truncated {
								t.Fatalf("log does not describe the returned DNS response: %v", record)
							}
						}
						if msg == "query summary" && record["branch"] != nil {
							t.Fatalf("branch leaked into parent summary: %v", record)
						}
					}
					if !seen["response ready"] {
						t.Fatal("missing final response event")
					}
					if tc.name == "miss" {
						for _, event := range []string{"condition evaluated", "rule skipped", "rule executing", "rule returned", "upstream query started", "upstream query finished", "upstream response selected", "query summary"} {
							if !seen[event] {
								t.Errorf("missing request stage %s", event)
							}
						}
					}
					if tc.name == "hit" && seen["upstream query started"] {
						t.Fatal("cache hit unexpectedly reached upstream")
					}
					if tc.name == "stale" && !branches["cache/refresh"] {
						t.Fatal("cache refresh has no branch identity")
					}
					if tc.name == "nested" && !branches["race_probe/probe/pc_remote/remote"] {
						t.Fatal("nested branch has no inherited path")
					}
					if tc.name == "truncated" && (!r.Truncated || len(*payload) > dns.MinMsgSize) {
						t.Fatal("large UDP response was not truncated")
					}
				})
			}
		})
	}
}
