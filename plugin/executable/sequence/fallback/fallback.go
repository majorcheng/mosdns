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

package fallback

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "fallback"

const (
	defaultParallelTimeout   = time.Second * 5
	defaultFallbackThreshold = time.Millisecond * 500
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type fallback struct {
	logger               *zap.Logger
	primary              sequence.Executable
	secondary            sequence.Executable
	fastFallbackDuration time.Duration
	alwaysStandby        bool
}

type Args struct {
	// Primary exec sequence.
	Primary string `yaml:"primary"`
	// Secondary exec sequence.
	Secondary string `yaml:"secondary"`

	// Threshold in milliseconds. Default is 500.
	Threshold int `yaml:"threshold"`

	// AlwaysStandby: secondary should always stand by in fallback.
	AlwaysStandby bool `yaml:"always_standby"`
}

func Init(bp *coremain.BP, args any) (any, error) {
	return newFallbackPlugin(bp, args.(*Args))
}

func newFallbackPlugin(bp *coremain.BP, args *Args) (*fallback, error) {
	if len(args.Primary) == 0 || len(args.Secondary) == 0 {
		return nil, errors.New("args missing primary or secondary")
	}

	pe := sequence.ToExecutable(bp.M().GetPlugin(args.Primary))
	if pe == nil {
		return nil, fmt.Errorf("can not find primary executable %s", args.Primary)
	}
	se := sequence.ToExecutable(bp.M().GetPlugin(args.Secondary))
	if se == nil {
		return nil, fmt.Errorf("can not find secondary executable %s", args.Secondary)
	}
	threshold := time.Duration(args.Threshold) * time.Millisecond
	if threshold <= 0 {
		threshold = defaultFallbackThreshold
	}

	s := &fallback{
		logger:               bp.L(),
		primary:              pe,
		secondary:            se,
		fastFallbackDuration: threshold,
		alwaysStandby:        args.AlwaysStandby,
	}
	return s, nil
}

var (
	ErrFailed = errors.New("no valid response from both primary and secondary")
)

var _ sequence.Executable = (*fallback)(nil)

func (f *fallback) Exec(ctx context.Context, qCtx *query_context.Context) error {
	return f.doFallback(ctx, qCtx)
}

func (f *fallback) doFallback(ctx context.Context, qCtx *query_context.Context) error {
	type result struct {
		resp   *dns.Msg
		branch string
		reason string
	}
	respChan := make(chan result, 2) // resp could be nil.
	primFailed := make(chan struct{})
	primDone := make(chan struct{})

	// primary goroutine.
	qCtxP := qCtx.CopyForBranch(f.logger.Name() + "/primary")
	go func() {
		qCtx := qCtxP
		ctx, cancel := makeDdlCtx(ctx, defaultParallelTimeout)
		defer cancel()
		if ce := f.logger.Check(zap.DebugLevel, "branch started"); ce != nil {
			ce.Write(qCtx.InfoField())
		}
		err := f.primary.Exec(ctx, qCtx)
		if ce := f.logger.Check(zap.DebugLevel, "branch finished"); ce != nil {
			ce.Write(qCtx.InfoField(), zap.Error(err))
		}
		if err != nil {
			f.logger.Warn("primary error", qCtx.InfoField(), zap.Error(err))
		}

		r := qCtx.R()
		if err != nil || r == nil {
			close(primFailed)
			respChan <- result{branch: "primary"}
		} else {
			close(primDone)
			respChan <- result{resp: r, branch: "primary", reason: "primary returned a response"}
		}
	}()

	// Secondary goroutine.
	qCtxS := qCtx.CopyForBranch(f.logger.Name() + "/secondary")
	go func() {
		reason := "always standby"
		timer := pool.GetTimer(f.fastFallbackDuration)
		defer pool.ReleaseTimer(timer)
		if !f.alwaysStandby { // not always standby, wait here.
			if ce := f.logger.Check(zap.DebugLevel, "secondary waiting"); ce != nil {
				ce.Write(qCtxS.InfoField(), zap.Duration("threshold", f.fastFallbackDuration))
			}
			select {
			case <-primDone: // primary is done, no need to exec this.
				if ce := f.logger.Check(zap.DebugLevel, "secondary skipped"); ce != nil {
					ce.Write(qCtxS.InfoField(), zap.String("reason", "primary completed"))
				}
				return
			case <-primFailed: // primary failed
				reason = "primary failed or returned no response"
			case <-timer.C: // timed out
				reason = "primary threshold elapsed"
			}
		}

		qCtx := qCtxS
		ctx, cancel := makeDdlCtx(ctx, defaultParallelTimeout)
		defer cancel()
		if ce := f.logger.Check(zap.DebugLevel, "branch started"); ce != nil {
			ce.Write(qCtx.InfoField(), zap.String("reason", reason))
		}
		err := f.secondary.Exec(ctx, qCtx)
		if ce := f.logger.Check(zap.DebugLevel, "branch finished"); ce != nil {
			ce.Write(qCtx.InfoField(), zap.Error(err))
		}
		if err != nil {
			f.logger.Warn("secondary error", qCtx.InfoField(), zap.Error(err))
			respChan <- result{branch: "secondary"}
			return
		}

		r := qCtx.R()
		// always standby is enabled. Wait until secondary resp is needed.
		if f.alwaysStandby && r != nil {
			if ce := f.logger.Check(zap.DebugLevel, "secondary waiting"); ce != nil {
				ce.Write(qCtx.InfoField(), zap.Duration("threshold", f.fastFallbackDuration))
			}
			select {
			case <-ctx.Done():
				reason = "secondary context ended"
			case <-primDone:
				reason = "primary completed"
			case <-primFailed: // only send secondary result when primary is failed.
				reason = "primary failed or returned no response"
			case <-timer.C: // or timed out.
				reason = "primary threshold elapsed"
			}
		}
		respChan <- result{resp: r, branch: "secondary", reason: reason}
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			if ce := f.logger.Check(zap.DebugLevel, "fallback stopped"); ce != nil {
				ce.Write(qCtx.InfoField(), zap.Error(context.Cause(ctx)))
			}
			return context.Cause(ctx)
		case result := <-respChan:
			if result.resp == nil { // One of goroutines finished but failed.
				continue
			}
			qCtx.SetResponse(result.resp)
			if ce := f.logger.Check(zap.DebugLevel, "branch selected"); ce != nil {
				ce.Write(qCtx.InfoField(), zap.String("selected", result.branch), zap.String("reason", result.reason))
			}
			return nil
		}
	}

	// All goroutines finished but failed.
	return ErrFailed
}

func makeDdlCtx(ctx context.Context, timeout time.Duration) (context.Context, func()) {
	ddl, ok := ctx.Deadline()
	if !ok {
		ddl = time.Now().Add(timeout)
	}
	return context.WithDeadline(context.Background(), ddl)
}
