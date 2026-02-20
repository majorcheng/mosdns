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

package probe_choice

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

func TestProbeChoiceExec(t *testing.T) {
	newPC := func(probe, remote, local sequence.Executable, probeWaitMs, timeoutMs int) *probeChoice {
		return &probeChoice{
			logger:    zap.NewNop(),
			probe:     probe,
			remote:    remote,
			local:     local,
			probeWait: time.Duration(probeWaitMs) * time.Millisecond,
			timeout:   time.Duration(timeoutMs) * time.Millisecond,
		}
	}

	tests := []struct {
		name       string
		pc         *probeChoice
		wantErr    bool
		wantNil    bool
		wantAnswer string
	}{
		{
			name: "probe in 50ms picks remote",
			pc: newPC(
				&testExec{delay: 10 * time.Millisecond, resp: newAResp("9.9.9.9")},
				&testExec{delay: 30 * time.Millisecond, resp: newAResp("8.8.8.8")},
				&testExec{delay: 5 * time.Millisecond, resp: newAResp("1.1.1.1")},
				50,
				200,
			),
			wantAnswer: "8.8.8.8",
		},
		{
			name: "no probe in 50ms picks local",
			pc: newPC(
				&testExec{delay: 120 * time.Millisecond, resp: newAResp("9.9.9.9")},
				&testExec{delay: 150 * time.Millisecond, resp: newAResp("8.8.8.8")},
				&testExec{delay: 20 * time.Millisecond, resp: newAResp("1.1.1.1")},
				50,
				220,
			),
			wantAnswer: "1.1.1.1",
		},
		{
			name: "probe after gate switches to remote",
			pc: newPC(
				&testExec{delay: 70 * time.Millisecond, resp: newAResp("9.9.9.9")},
				&testExec{delay: 90 * time.Millisecond, resp: newAResp("8.8.8.8")},
				&testExec{delay: 140 * time.Millisecond, resp: newAResp("1.1.1.1")},
				50,
				260,
			),
			wantAnswer: "8.8.8.8",
		},
		{
			name: "remote error is returned after probe feedback",
			pc: newPC(
				&testExec{delay: 10 * time.Millisecond},
				&testExec{delay: 20 * time.Millisecond, err: errors.New("remote failed")},
				&testExec{delay: 80 * time.Millisecond, resp: newAResp("1.1.1.1")},
				50,
				200,
			),
			wantErr: true,
		},
		{
			name: "remote empty response is returned after probe feedback",
			pc: newPC(
				&testExec{delay: 10 * time.Millisecond},
				&testExec{delay: 20 * time.Millisecond},
				&testExec{delay: 80 * time.Millisecond, resp: newAResp("1.1.1.1")},
				50,
				200,
			),
			wantNil: true,
		},
		{
			name: "local error is returned when probe not seen",
			pc: newPC(
				&testExec{delay: 150 * time.Millisecond},
				&testExec{delay: 180 * time.Millisecond, resp: newAResp("8.8.8.8")},
				&testExec{delay: 60 * time.Millisecond, err: errors.New("local failed")},
				50,
				240,
			),
			wantErr: true,
		},
		{
			name: "timeout when no branch can decide",
			pc: newPC(
				&testExec{waitCtx: true},
				&testExec{waitCtx: true},
				&testExec{waitCtx: true},
				50,
				40,
			),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qCtx := newQueryContext()
			err := tt.pc.Exec(context.Background(), qCtx)
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

func TestProbeChoiceInit(t *testing.T) {
	m := coremain.NewTestMosdnsWithPlugins(map[string]any{
		"probe":  &testExec{},
		"remote": &testExec{},
		"local":  &testExec{},
	})

	_, err := newProbeChoicePlugin(coremain.NewBP("test", m), &Args{
		ProbeExec:  "probe",
		RemoteExec: "remote",
		LocalExec:  "local",
	})
	if err != nil {
		t.Fatalf("newProbeChoicePlugin() error = %v", err)
	}

	_, err = newProbeChoicePlugin(coremain.NewBP("test", m), &Args{
		ProbeExec:  "probe",
		RemoteExec: "",
		LocalExec:  "local",
	})
	if err == nil {
		t.Fatalf("expected init error when remote_exec is missing")
	}

	_, err = newProbeChoicePlugin(coremain.NewBP("test", m), &Args{
		ProbeExec:  "probe",
		RemoteExec: "missing",
		LocalExec:  "local",
	})
	if err == nil {
		t.Fatalf("expected init error when remote_exec tag is invalid")
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
