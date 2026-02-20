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
	"fmt"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "probe_choice"

const (
	defaultTimeout   = time.Millisecond * 300
	defaultProbeWait = time.Millisecond * 50
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type Args struct {
	ProbeExec  string `yaml:"probe_exec"`
	RemoteExec string `yaml:"remote_exec"`
	LocalExec  string `yaml:"local_exec"`
	ProbeWait  int    `yaml:"probe_wait"`
	Timeout    int    `yaml:"timeout"`
}

type probeChoice struct {
	logger    *zap.Logger
	probe     sequence.Executable
	remote    sequence.Executable
	local     sequence.Executable
	probeWait time.Duration
	timeout   time.Duration
}

type execEvent struct {
	resp *dns.Msg
	err  error
}

var _ sequence.Executable = (*probeChoice)(nil)

func Init(bp *coremain.BP, args any) (any, error) {
	return newProbeChoicePlugin(bp, args.(*Args))
}

func newProbeChoicePlugin(bp *coremain.BP, args *Args) (*probeChoice, error) {
	if len(args.ProbeExec) == 0 {
		return nil, errors.New("args missing probe_exec")
	}
	if len(args.RemoteExec) == 0 {
		return nil, errors.New("args missing remote_exec")
	}
	if len(args.LocalExec) == 0 {
		return nil, errors.New("args missing local_exec")
	}

	probe := sequence.ToExecutable(bp.M().GetPlugin(args.ProbeExec))
	if probe == nil {
		return nil, fmt.Errorf("can not find probe executable %s", args.ProbeExec)
	}
	remote := sequence.ToExecutable(bp.M().GetPlugin(args.RemoteExec))
	if remote == nil {
		return nil, fmt.Errorf("can not find remote executable %s", args.RemoteExec)
	}
	local := sequence.ToExecutable(bp.M().GetPlugin(args.LocalExec))
	if local == nil {
		return nil, fmt.Errorf("can not find local executable %s", args.LocalExec)
	}

	probeWait := time.Duration(args.ProbeWait) * time.Millisecond
	if probeWait <= 0 {
		probeWait = defaultProbeWait
	}
	timeout := time.Duration(args.Timeout) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return &probeChoice{
		logger:    bp.L(),
		probe:     probe,
		remote:    remote,
		local:     local,
		probeWait: probeWait,
		timeout:   timeout,
	}, nil
}

func (p *probeChoice) Exec(ctx context.Context, qCtx *query_context.Context) error {
	runCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	probeCh := make(chan execEvent, 1)
	remoteCh := make(chan execEvent, 1)
	localCh := make(chan execEvent, 1)

	go p.runExecutable(runCtx, p.probe, qCtx.Copy(), probeCh)
	go p.runExecutable(runCtx, p.remote, qCtx.Copy(), remoteCh)
	go p.runExecutable(runCtx, p.local, qCtx.Copy(), localCh)

	var remoteEvent *execEvent
	var localEvent *execEvent
	probeSeen := false
	gatePassed := false

	probeRecv := (<-chan execEvent)(probeCh)
	remoteRecv := (<-chan execEvent)(remoteCh)
	localRecv := (<-chan execEvent)(localCh)

	t := time.NewTimer(p.probeWait)
	defer stopTimer(t)
	gateC := t.C

	for {
		if probeSeen && remoteEvent != nil {
			if remoteEvent.err != nil {
				return remoteEvent.err
			}
			qCtx.SetResponse(remoteEvent.resp)
			return nil
		}

		if gatePassed && !probeSeen && localEvent != nil {
			if probeRecv != nil {
				select {
				case e := <-probeRecv:
					probeSeen = true
					probeRecv = nil
					if e.err != nil {
						p.logger.Warn("probe error", qCtx.InfoField(), zap.Error(e.err))
					}
					continue
				default:
				}
			}

			if localEvent.err != nil {
				return localEvent.err
			}
			qCtx.SetResponse(localEvent.resp)
			return nil
		}

		select {
		case <-runCtx.Done():
			return context.Cause(runCtx)
		case <-gateC:
			gatePassed = true
			gateC = nil
		case e := <-probeRecv:
			probeSeen = true
			probeRecv = nil
			if e.err != nil {
				p.logger.Warn("probe error", qCtx.InfoField(), zap.Error(e.err))
			}
		case e := <-remoteRecv:
			remoteEvent = &e
			remoteRecv = nil
			if e.err != nil {
				p.logger.Warn("remote error", qCtx.InfoField(), zap.Error(e.err))
			}
		case e := <-localRecv:
			localEvent = &e
			localRecv = nil
			if e.err != nil {
				p.logger.Warn("local error", qCtx.InfoField(), zap.Error(e.err))
			}
		}
	}
}

func (p *probeChoice) runExecutable(ctx context.Context, exec sequence.Executable, qCtx *query_context.Context, ch chan<- execEvent) {
	err := exec.Exec(ctx, qCtx)
	event := execEvent{resp: qCtx.R(), err: err}
	select {
	case ch <- event:
	case <-ctx.Done():
	}
}

func stopTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}
