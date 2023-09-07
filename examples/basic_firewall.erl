%%% Trivial stateless firewall
%%%
%%% Allow:
%%%
%%%     icmp: all
%%%     udp: none
%%%     tcp:
%%%         outgoing: 22, 80, 443
%%%         incoming: 22
%%%
%%% Then start using:
%%%
%%% sut:start([
%%%     {filter_out, fun(Packet, State) -> basic_firewall:out(Packet, State) end},
%%%     {filter_in, fun(Packet, State) -> basic_firewall:in(Packet, State) end},
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

-define(RECORD_TO_PROPLIST(Record),
        fun(Val) ->
            lists:zip(
                record_info(fields, Record),
                tl(tuple_to_list(Val))
                )
    end).


in(Packet, _State) ->
    {IPv6Header, Payload} =  pkt:ipv6(Packet),
    in_1(IPv6Header, Payload).

in_1(#ipv6{next = ?IPPROTO_ICMPV6}, _) ->
    ok;
in_1(#ipv6{next = ?IPPROTO_UDP}, Packet) ->
    {UDPHeader, _} = pkt:udp(Packet),
    {block, in, udphdr(UDPHeader)};
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
        _ ->
            {block, in, tcphdr(TCPHeader)}
    end.


out(Packet, _State) ->
    {IPv6Header, Payload} =  pkt:ipv6(Packet),
    out_1(IPv6Header, Payload).

out_1(#ipv6{next = ?IPPROTO_ICMPV6}, _) ->
    ok;
out_1(#ipv6{next = ?IPPROTO_UDP}, Packet) ->
    {UDPHeader, _} = pkt:udp(Packet),
    {block, out, udphdr(UDPHeader)};
out_1(#ipv6{next = ?IPPROTO_TCP}, Packet) ->
    {TCPHeader, _} = pkt:tcp(Packet),
    case TCPHeader#tcp.dport of
        22 -> ok;
        80 -> ok;
        443 -> ok;
        _ -> {block, out, tcphdr(TCPHeader)}
    end.

tcphdr(Rec) ->
    Fun = ?RECORD_TO_PROPLIST(tcp),
    Fun(Rec).

udphdr(Rec) ->
    Fun = ?RECORD_TO_PROPLIST(udp),
    Fun(Rec).
