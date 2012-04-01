%% Copyright (c) 2012, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.

%%% Trivial stateless firewall
%%%
%%% Allow:
%%%
%%%     icmp: all
%%%     udp: none
%%%     tcp:
%%%         outgoing: 22, 80, 443
%%%         incomiing: 22
%%%
%%% Then start using:
%%%
%%% sut:start([
%%%     {out, fun(Packet, State) -> basic_firewall:out(Packet, State) end},
%%%     {in, fun(Packet, State) -> basic_firewall:in(Packet, State) end},
%%%
%%%     {serverv4, Server4},
%%%     {clientv4, Client4},
%%%     {clientv6, Client6}
%%% ]).
%%%
%%%
-module(basic_firewall).
-include_lib("pkt/include/pkt.hrl").

-export([
    in/2,
    out/2
    ]).

in(Packet, _State) ->
    {IPv6Header, Payload} =  pkt:ipv6(Packet),
    in_1(IPv6Header, Payload).

in_1(#ipv6{next = ?IPPROTO_ICMPV6}, _) ->
    ok;
in_1(#ipv6{next = ?IPPROTO_UDP}, Packet) ->
    {UDPHeader, _} = pkt:udp(Packet),
    {block, in, UDPHeader};
% $ cat /proc/sys/net/ipv4/ip_local_port_range
% 32768   61000
in_1(#ipv6{next = ?IPPROTO_TCP}, Packet) ->
    {TCPHeader, _} = pkt:tcp(Packet),
    case TCPHeader of
        #tcp{dport = 22} -> ok;
        #tcp{sport = 80, dport = Dport, ack = 1}
                when Dport >= 32768; Dport =< 61000 -> ok;
        #tcp{sport = 443, dport = Dport, ack = 1}
                when Dport >= 32768; Dport =< 61000 -> ok;
        _ -> {block, in, TCPHeader}
    end.


out(Packet, _State) ->
    {IPv6Header, Payload} =  pkt:ipv6(Packet),
    out_1(IPv6Header, Payload).

out_1(#ipv6{next = ?IPPROTO_ICMPV6}, _) ->
    ok;
out_1(#ipv6{next = ?IPPROTO_UDP}, Packet) ->
    {UDPHeader, _} = pkt:udp(Packet),
    {block, out, UDPHeader};
out_1(#ipv6{next = ?IPPROTO_TCP}, Packet) ->
    {TCPHeader, _} = pkt:tcp(Packet),
    case TCPHeader#tcp.dport of
        22 -> ok;
        80 -> ok;
        443 -> ok;
        _ -> {block, out, TCPHeader}
    end.
