/*
 * Copyright (C) 2022-2024 Ronan Le Meillat
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestCheckRequest(t *testing.T) {
	tests := []struct {
		name     string
		request  *dns.Msg
		expected bool
	}{
		{
			name: "Valid request",
			request: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "zonetest.zone.tld.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: true,
		},
		{
			name: "Invalid request - more than one question",
			request: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "example.com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
					{
						Name:   "example.com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: false,
		},
		{
			name: "Invalid request - not a subdomain of the zone",
			request: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "notexample.com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: false,
		},
		{
			name: "Invalid request - contains two dots",
			request: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "example..com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: false,
		},
		{
			name: "Invalid request - not a valid FQDN",
			request: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "example",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: false,
		},
		{
			name: "Invalid request - malicious attempt",
			request: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "example.com.<script>alert('XSS')</script>.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkRequest(tt.request); got != tt.expected {
				t.Errorf("checkRequest() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHandleDNS(t *testing.T) {
	tests := []struct {
		name     string
		request  *dns.Msg
		expected string
	}{
		{
			name: "Valid A request",
			request: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "289899JJSZ.zonetest.zone.tld.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: serverAddr,
		},
		{
			name: "Valid AAAA request",
			request: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "792898JSNJSN.zonetest.zone.tld.",
						Qtype:  dns.TypeAAAA,
						Qclass: dns.ClassINET,
					},
				},
			},
			expected: serverAddrIPv6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &testResponseWriter{}
			handleDNS(w, tt.request)
			if tt.request.Question[0].Qtype == dns.TypeA {
				if got := w.msg.Answer[0].(*dns.A).A.String(); got != tt.expected {
					t.Errorf("handleDNS() = %v, want %v", got, tt.expected)
				}
			} else if tt.request.Question[0].Qtype == dns.TypeAAAA {
				if got := w.msg.Answer[0].(*dns.AAAA).AAAA.String(); got != tt.expected {
					t.Errorf("handleDNS() = %v, want %v", got, tt.expected)
				}
			}
		})
	}
}

type testResponseWriter struct {
	msg *dns.Msg
}

func (w *testResponseWriter) LocalAddr() net.Addr { return nil }
func (w *testResponseWriter) RemoteAddr() net.Addr {
	return &net.IPAddr{
		IP: net.ParseIP("127.127.127.127"),
	}
}
func (w *testResponseWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *testResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *testResponseWriter) Close() error              { return nil }
func (w *testResponseWriter) TsigStatus() error         { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool)       {}
func (w *testResponseWriter) Hijack()                   {}
