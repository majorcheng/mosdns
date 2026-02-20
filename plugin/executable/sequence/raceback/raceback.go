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
	"fmt"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "raceback"

const (
	defaultTimeout      = time.Millisecond * 300
	defaultProbeMinWait = time.Millisecond * 50
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type Args struct {
	ProbeExec string `yaml:"probe_exec"`
	LocalExec string `yaml:"local_exec"`
	Timeout   int    `yaml:"timeout"`
	ProbeWait int    `yaml:"probe_wait"`
}

type raceback struct {
	logger       *zap.Logger
	probe        sequence.Executable
	local        sequence.Executable
	timeout      time.Duration
	probeMinWait time.Duration
}

type execEvent struct {
	resp *dns.Msg
	err  error
}

var _ sequence.Executable = (*raceback)(nil)

func Init(bp *coremain.BP, args any) (any, error) {
	return newRacebackPlugin(bp, args.(*Args))
}

func newRacebackPlugin(bp *coremain.BP, args *Args) (*raceback, error) {
	if len(args.ProbeExec) == 0 {
		return nil, errors.New("args missing probe_exec")
	}
	if len(args.LocalExec) == 0 {
		return nil, errors.New("args missing local_exec")
	}

	probe := sequence.ToExecutable(bp.M().GetPlugin(args.ProbeExec))
	if probe == nil {
		return nil, fmt.Errorf("can not find probe executable %s", args.ProbeExec)
	}
	local := sequence.ToExecutable(bp.M().GetPlugin(args.LocalExec))
	if local == nil {
		return nil, fmt.Errorf("can not find local executable %s", args.LocalExec)
	}

	timeout := time.Duration(args.Timeout) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	probeMinWait := time.Duration(args.ProbeWait) * time.Millisecond
	if probeMinWait <= 0 {
		probeMinWait = defaultProbeMinWait
	}

	return &raceback{
		logger:       bp.L(),
		probe:        probe,
		local:        local,
		timeout:      timeout,
		probeMinWait: probeMinWait,
	}, nil
}

func (r *raceback) Exec(ctx context.Context, qCtx *query_context.Context) error {
	runCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	probeCh := make(chan execEvent, 1)
	localCh := make(chan execEvent, 1)

	go r.runExecutable(runCtx, r.probe, qCtx.Copy(), probeCh)
	go r.runExecutable(runCtx, r.local, qCtx.Copy(), localCh)

	var probeEvent *execEvent
	var localEvent *execEvent

	probeRecv := (<-chan execEvent)(probeCh)
	localRecv := (<-chan execEvent)(localCh)

	minWaitTimer := time.NewTimer(r.probeMinWait)
	defer stopTimer(minWaitTimer)
	minWaitPassed := false
	minWaitC := minWaitTimer.C

	for {
		if probeEvent != nil && probeEvent.resp != nil {
			qCtx.SetResponse(probeEvent.resp)
			return nil
		}

		if minWaitPassed && localEvent != nil {
			if probeEvent == nil && probeRecv != nil {
				select {
				case e := <-probeRecv:
					probeEvent = &e
					probeRecv = nil
					if e.err != nil {
						r.logger.Warn("probe error", qCtx.InfoField(), zap.Error(e.err))
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
		case <-minWaitC:
			minWaitPassed = true
			minWaitC = nil
		case e := <-probeRecv:
			probeEvent = &e
			probeRecv = nil
			if e.err != nil {
				r.logger.Warn("probe error", qCtx.InfoField(), zap.Error(e.err))
			}
		case e := <-localRecv:
			localEvent = &e
			localRecv = nil
			if e.err != nil {
				r.logger.Warn("local error", qCtx.InfoField(), zap.Error(e.err))
			}
		}
	}
}

func (r *raceback) runExecutable(ctx context.Context, exec sequence.Executable, qCtx *query_context.Context, ch chan<- execEvent) {
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
