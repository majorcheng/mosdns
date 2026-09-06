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

package dual_selector

import (
	"context"
	"io"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/cache"
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	referenceWaitTimeout     = time.Millisecond * 500
	defaultSubRoutineTimeout = time.Second * 5

	// TODO: Make cache configurable?
	cacheSize       = 64 * 1024
	cacheTlt        = time.Hour
	cacheGcInterval = time.Minute
)

func init() {
	sequence.MustRegExecQuickSetup("prefer_ipv4", func(bq sequence.BQ, _ string) (any, error) {
		return NewPreferIpv4(bq), nil
	})
	sequence.MustRegExecQuickSetup("prefer_ipv6", func(bq sequence.BQ, _ string) (any, error) {
		return NewPreferIpv6(bq), nil
	})
}

var _ sequence.RecursiveExecutable = (*Selector)(nil)
var _ io.Closer = (*Selector)(nil)

type Selector struct {
	sequence.BQ
	prefer uint16 // dns.TypeA or dns.TypeAAAA

	preferTypOkCache *cache.Cache[key, bool]
}

// Exec implements handler.Executable.
func (s *Selector) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	q := qCtx.Q()
	if len(q.Question) != 1 { // skip wired query with multiple questions.
		return next.ExecNext(ctx, qCtx)
	}
	parentBranch := qCtx.LogBranch
	logDecision := func(result, reason string, err error) {
		if ce := s.L().Check(zap.DebugLevel, "address preference decision"); ce != nil {
			ce.Write(qCtx.InfoField(), zap.String("preferred_type", dns.Type(s.prefer).String()),
				zap.String("result", result), zap.String("reason", reason), zap.Error(err))
		}
	}

	qtype := q.Question[0].Qtype
	// skip queries that have other unrelated types.
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		logDecision("pass", "query type is not A or AAAA", nil)
		return next.ExecNext(ctx, qCtx)
	}

	qName := key(q.Question[0].Name)
	if qtype == s.prefer {
		err := next.ExecNext(ctx, qCtx)
		logDecision("pass", "query uses the preferred type", err)
		if err != nil {
			return err
		}

		if r := qCtx.R(); r != nil && msgAnsHasRR(r, s.prefer) {
			s.preferTypOkCache.Store(qName, true, time.Now().Add(cacheTlt))
		}
		return nil
	}

	// Qtype is not the preferred type.
	preferredTypOk, _, _ := s.preferTypOkCache.Get(qName)
	if preferredTypOk {
		// We know that domain has preferred type so this qtype can be blocked
		// right away.
		r := dnsutils.GenEmptyReply(q, dns.RcodeSuccess)
		qCtx.SetResponse(r)
		logDecision("suppress", "preferred type found in cache", nil)
		return nil
	}

	// async check whether domain has the preferred type
	qCtxPreferred := qCtx.CopyForBranch(s.L().Name() + "/reference")
	qCtxPreferred.Q().Question[0].Qtype = s.prefer

	ddl, cacheOk := ctx.Deadline()
	if !cacheOk {
		ddl = time.Now().Add(defaultSubRoutineTimeout)
	}

	shouldBlock := make(chan struct{})
	shouldPass := make(chan struct{})
	go func() {
		qCtx := qCtxPreferred
		ctx, cancel := context.WithDeadline(context.Background(), ddl)
		defer cancel()
		if ce := s.L().Check(zap.DebugLevel, "branch started"); ce != nil {
			ce.Write(qCtx.InfoField())
		}
		err := next.ExecNext(ctx, qCtx)
		if ce := s.L().Check(zap.DebugLevel, "branch finished"); ce != nil {
			ce.Write(qCtx.InfoField(), zap.Error(err))
		}
		if err != nil {
			s.L().Warn("reference query routine err", qCtx.InfoField(), zap.Error(err))
			close(shouldPass)
			return
		}
		if r := qCtx.R(); r != nil && msgAnsHasRR(r, s.prefer) {
			// Target domain has preferred type.
			s.preferTypOkCache.Store(qName, true, time.Now().Add(cacheTlt))
			close(shouldBlock)
			return
		}
		close(shouldPass)
	}()

	// start original query goroutine
	doneChan := make(chan error, 1)
	qCtxOrg := qCtx.CopyForBranch(s.L().Name() + "/original")
	go func() {
		qCtx := qCtxOrg
		ctx, cancel := context.WithDeadline(context.Background(), ddl)
		defer cancel()
		if ce := s.L().Check(zap.DebugLevel, "branch started"); ce != nil {
			ce.Write(qCtx.InfoField())
		}
		err := next.ExecNext(ctx, qCtx)
		if ce := s.L().Check(zap.DebugLevel, "branch finished"); ce != nil {
			ce.Write(qCtx.InfoField(), zap.Error(err))
		}
		doneChan <- err
	}()

	select {
	case <-ctx.Done():
		logDecision("stop", "request context ended", context.Cause(ctx))
		return context.Cause(ctx)
	case <-shouldBlock: // Domain has preferred type. Block this type now.
		r := dnsutils.GenEmptyReply(q, dns.RcodeSuccess)
		qCtx.SetResponse(r)
		logDecision("suppress", "preferred type has an answer", nil)
		return nil
	case err := <-doneChan: // The original query finished. Waiting for preferred type check.
		waitTimeoutTimer := pool.GetTimer(referenceWaitTimeout)
		defer pool.ReleaseTimer(waitTimeoutTimer)
		select {
		case <-ctx.Done():
			logDecision("stop", "request context ended", context.Cause(ctx))
			return context.Cause(ctx)
		case <-shouldBlock:
			r := dnsutils.GenEmptyReply(q, dns.RcodeSuccess)
			qCtx.SetResponse(r)
			logDecision("suppress", "preferred type has an answer", nil)
			return nil
		case <-shouldPass:
			*qCtx = *qCtxOrg // replace qCtx
			qCtx.LogBranch = parentBranch
			logDecision("pass", "reference query did not require suppression", err)
			return err
		case <-waitTimeoutTimer.C:
			// We have been waiting the reference query for too long.
			// Something may go wrong. We accept the original reply.
			*qCtx = *qCtxOrg
			qCtx.LogBranch = parentBranch
			logDecision("pass", "reference wait elapsed", err)
			return err
		}
	}
}

func (s *Selector) Close() error {
	s.preferTypOkCache.Close()
	return nil
}

func NewPreferIpv4(bq sequence.BQ) *Selector {
	return newSelector(bq, dns.TypeA)
}

func NewPreferIpv6(bq sequence.BQ) *Selector {
	return newSelector(bq, dns.TypeAAAA)
}

func newSelector(bq sequence.BQ, preferType uint16) *Selector {
	if preferType != dns.TypeA && preferType != dns.TypeAAAA {
		panic("dual_selector: invalid dns qtype")
	}
	return &Selector{
		BQ:               bq,
		prefer:           preferType,
		preferTypOkCache: cache.New[key, bool](cache.Opts{Size: cacheSize, CleanerInterval: cacheGcInterval}),
	}
}

func msgAnsHasRR(m *dns.Msg, t uint16) bool {
	if len(m.Answer) == 0 {
		return false
	}

	for _, rr := range m.Answer {
		if rr.Header().Rrtype == t {
			return true
		}
	}
	return false
}
