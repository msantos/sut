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
-module(sut_fw).
-include("sut.hrl").

-export([
    out/2,
    in/2
    ]).


%% tun device -> socket
out(Packet, #sut_state{filter_out = Fun} = State) ->
    case Fun(Packet, State) of
        ok -> to_sock(Packet, State);
        {ok, NPacket} -> to_sock(NPacket, State);
        Error -> Error
    end.

to_sock(Packet, #sut_state{
                s = Socket,
                error_out = FunErr,
                serverv4 = Server
                }) ->
    ok = FunErr(gen_udp:send(Socket, Server, 0, Packet)).

%% socket -> tun device
in(Packet, #sut_state{filter_in = Fun} = State) ->
    ok = valid(Packet),
    case Fun(Packet, State) of
        ok -> to_tun(Packet, State);
        {ok, NPacket} -> to_tun(NPacket, State);
        Error -> Error
    end.

to_tun(Packet, #sut_state{
                dev = Dev,
                error_in = FunErr
                }) ->
    ok = FunErr(tuncer:send(Dev, Packet)).


%%
%% Check for valid IPv6 packet
%%

% loopback
valid(<<6:4, _Class:8, _Flow:20,
        _Len:16, _Next:8, _Hop:8,
        _SA1:16, _SA2:16, _SA3:16, _SA4:16, _SA5:16, _SA6:16, _SA7:16, _SA8:16,
        0:16, 0:16, 0:16, 0:16, 0:16, 0:16, 0:16, 1:16,
        _Payload/binary>>) ->
    {invalid, loopback};
% unspecified address
valid(<<6:4, _Class:8, _Flow:20,
        _Len:16, _Next:8, _Hop:8,
        _SA1:16, _SA2:16, _SA3:16, _SA4:16, _SA5:16, _SA6:16, _SA7:16, _SA8:16,
        0:16, 0:16, 0:16, 0:16, 0:16, 0:16, 0:16, 0:16,
        _Payload/binary>>) ->
    {invalid, unspecified_address};
% Multicast 
valid(<<6:4, _Class:8, _Flow:20,
        _Len:16, _Next:8, _Hop:8,
        _SA1:16, _SA2:16, _SA3:16, _SA4:16, _SA5:16, _SA6:16, _SA7:16, _SA8:16,
        16#FF00:16, _:16, _:16, _:16, _:16, _:16, _:16, _:16,
        _Payload/binary>>) ->
    {invalid, multicast};
% IPv6 Addresses with Embedded IPv4 Addresses
valid(<<6:4, _Class:8, _Flow:20,
        _Len:16, _Next:8, _Hop:8,
        _SA1:16, _SA2:16, _SA3:16, _SA4:16, _SA5:16, _SA6:16, _SA7:16, _SA8:16,
        0:16, 0:16, 0:16, 0:16, 0:16, 0:16, _:16, _:16,
        _Payload/binary>>) ->
    {invalid, ipv4_compatible_ipv6_address};
valid(<<6:4, _Class:8, _Flow:20,
        _Len:16, _Next:8, _Hop:8,
        _SA1:16, _SA2:16, _SA3:16, _SA4:16, _SA5:16, _SA6:16, _SA7:16, _SA8:16,
        0:16, 0:16, 0:16, 0:16, 0:16, 16#FFFF:16, _:16, _:16,
        _Payload/binary>>) ->
    {invalid, ipv4_mapped_ipv6_address};
valid(<<6:4, _:4, _/binary>>) ->
    ok;
% Invalid protocol
valid(_Packet) ->
    {invalid, invalid_protocol}.
