/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package raceback

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type testExec struct {
	delay   time.Duration
	resp    *dns.Msg
	err     error
	waitCtx bool
}

func (e *testExec) Exec(ctx context.Context, qCtx *query_context.Context) error {
	if e.waitCtx {
		<-ctx.Done()
		return context.Cause(ctx)
	}

	if e.delay > 0 {
		t := time.NewTimer(e.delay)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-t.C:
		}
	}

	if e.err != nil {
		return e.err
	}
	if e.resp != nil {
		qCtx.SetResponse(e.resp.Copy())
	}
	return nil
}

func TestRacebackExec(t *testing.T) {
	newRB := func(probe, local sequence.Executable, timeoutMs, minWaitMs int) *raceback {
		return &raceback{
			logger:       zap.NewNop(),
			probe:        probe,
			local:        local,
			timeout:      time.Duration(timeoutMs) * time.Millisecond,
			probeMinWait: time.Duration(minWaitMs) * time.Millisecond,
		}
	}

	tests := []struct {
		name       string
		rb         *raceback
		wantErr    bool
		wantNil    bool
		wantAnswer string
	}{
		{
			name: "probe hits before gate and returns probe response",
			rb: newRB(
				&testExec{delay: 15 * time.Millisecond, resp: newAResp("6.6.6.6")},
				&testExec{delay: 5 * time.Millisecond, resp: newAResp("1.1.1.1")},
				120,
				50,
			),
			wantAnswer: "6.6.6.6",
		},
		{
			name: "local early result becomes effective when gate opens",
			rb: newRB(
				&testExec{delay: 80 * time.Millisecond, resp: newAResp("6.6.6.6")},
				&testExec{delay: 5 * time.Millisecond, resp: newAResp("1.1.1.1")},
				150,
				50,
			),
			wantAnswer: "1.1.1.1",
		},
		{
			name: "after gate first resolver wins local first",
			rb: newRB(
				&testExec{delay: 90 * time.Millisecond, resp: newAResp("6.6.6.6")},
				&testExec{delay: 60 * time.Millisecond, resp: newAResp("1.1.1.1")},
				150,
				50,
			),
			wantAnswer: "1.1.1.1",
		},
		{
			name: "after gate first resolver wins probe first",
			rb: newRB(
				&testExec{delay: 60 * time.Millisecond, resp: newAResp("6.6.6.6")},
				&testExec{delay: 90 * time.Millisecond, resp: newAResp("1.1.1.1")},
				150,
				50,
			),
			wantAnswer: "6.6.6.6",
		},
		{
			name: "local empty response is accepted after gate",
			rb: newRB(
				&testExec{waitCtx: true},
				&testExec{delay: 5 * time.Millisecond},
				100,
				30,
			),
			wantNil: true,
		},
		{
			name: "local error is returned after gate",
			rb: newRB(
				&testExec{waitCtx: true},
				&testExec{delay: 5 * time.Millisecond, err: errors.New("local failed")},
				120,
				30,
			),
			wantErr: true,
		},
		{
			name: "timeout when both unresolved",
			rb: newRB(
				&testExec{waitCtx: true},
				&testExec{waitCtx: true},
				40,
				20,
			),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qCtx := newQueryContext()
			err := tt.rb.Exec(context.Background(), qCtx)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Exec() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			r := qCtx.R()
			if tt.wantNil {
				if r != nil {
					t.Fatalf("Exec() got non-nil response")
				}
				return
			}

			if r == nil || len(r.Answer) == 0 {
				t.Fatalf("Exec() got empty response")
			}
			a, ok := r.Answer[0].(*dns.A)
			if !ok {
				t.Fatalf("Exec() got answer type %T", r.Answer[0])
			}
			if a.A.String() != tt.wantAnswer {
				t.Fatalf("Exec() answer = %s, want %s", a.A.String(), tt.wantAnswer)
			}
		})
	}
}

func TestRacebackInit(t *testing.T) {
	m := coremain.NewTestMosdnsWithPlugins(map[string]any{
		"probe": &testExec{},
		"local": &testExec{},
	})

	_, err := newRacebackPlugin(coremain.NewBP("test", m), &Args{
		ProbeExec: "probe",
		LocalExec: "local",
		Timeout:   0,
		ProbeWait: 0,
	})
	if err != nil {
		t.Fatalf("newRacebackPlugin() error = %v", err)
	}

	_, err = newRacebackPlugin(coremain.NewBP("test", m), &Args{
		ProbeExec: "missing",
		LocalExec: "local",
	})
	if err == nil {
		t.Fatalf("expected init error when probe_exec tag is invalid")
	}
}

func newQueryContext() *query_context.Context {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	return query_context.NewContext(q)
}

func newAResp(ip string) *dns.Msg {
	m := new(dns.Msg)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP(ip).To4(),
	})
	return m
}
