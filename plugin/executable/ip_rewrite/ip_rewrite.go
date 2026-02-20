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

package ip_rewrite

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "ip_rewrite"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

var _ sequence.Executable = (*IPRewrite)(nil)

type Args struct {
	// IPv4 地址，用于替换所有 A 记录
	IPv4 string `yaml:"ipv4"`
	// IPv6 地址，用于替换所有 AAAA 记录
	IPv6 string `yaml:"ipv6"`
}

type IPRewrite struct {
	ipv4 netip.Addr
	ipv6 netip.Addr
	logger *zap.Logger
}

func Init(bp *coremain.BP, args any) (any, error) {
	return NewIPRewrite(bp, args.(*Args))
}

func NewIPRewrite(bp *coremain.BP, args *Args) (*IPRewrite, error) {
	r := &IPRewrite{
		logger: bp.L(),
	}

	if args.IPv4 != "" {
		addr, err := netip.ParseAddr(args.IPv4)
		if err != nil {
			return nil, fmt.Errorf("invalid ipv4 address: %w", err)
		}
		if !addr.Is4() {
			return nil, fmt.Errorf("ipv4 must be an IPv4 address, got %s", args.IPv4)
		}
		r.ipv4 = addr
		bp.L().Info("ipv4 rewrite enabled", zap.String("target", args.IPv4))
	}

	if args.IPv6 != "" {
		addr, err := netip.ParseAddr(args.IPv6)
		if err != nil {
			return nil, fmt.Errorf("invalid ipv6 address: %w", err)
		}
		if !addr.Is6() {
			return nil, fmt.Errorf("ipv6 must be an IPv6 address, got %s", args.IPv6)
		}
		r.ipv6 = addr
		bp.L().Info("ipv6 rewrite enabled", zap.String("target", args.IPv6))
	}

	if !r.ipv4.IsValid() && !r.ipv6.IsValid() {
		return nil, fmt.Errorf("at least one of ipv4 or ipv6 must be specified")
	}

	return r, nil
}

func (r *IPRewrite) Exec(_ context.Context, qCtx *query_context.Context) error {
	resp := qCtx.R()
	if resp == nil {
		return nil
	}

	modified := 0
	for i, rr := range resp.Answer {
		switch record := rr.(type) {
		case *dns.A:
			if r.ipv4.IsValid() {
				newRecord := &dns.A{
					Hdr: record.Hdr,
					A:   r.ipv4.AsSlice(),
				}
				resp.Answer[i] = newRecord
				modified++
			}
		case *dns.AAAA:
			if r.ipv6.IsValid() {
				newRecord := &dns.AAAA{
					Hdr:  record.Hdr,
					AAAA: r.ipv6.AsSlice(),
				}
				resp.Answer[i] = newRecord
				modified++
			}
		}
	}

	if modified > 0 {
		r.logger.Debug("rewritten ip addresses", 
			zap.Uint32("uqid", qCtx.Id()),
			zap.Int("count", modified))
	}

	return nil
}
