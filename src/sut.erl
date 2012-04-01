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
-module(sut).
-behaviour(gen_server).

-export([
        destroy/1
    ]).

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
        terminate/2, code_change/3]).


-define(IPPROTO_IPV6, 41).

-define(PROPLIST_TO_RECORD(Record),
        fun(Proplist) ->
            Fields = record_info(fields, Record),
            [Tag| Values] = tuple_to_list(#Record{}),
            Defaults = lists:zip(Fields, Values),
            L = lists:map(fun ({K,V}) -> proplists:get_value(K, Proplist, V) end, Defaults),
            list_to_tuple([Tag|L])
        end).

-record(state, {
        ifname = <<"sut-ipv6">>,
        serverv4,
        clientv4,
        clientv6,

        s,
        fd,
        dev
        }).


%%--------------------------------------------------------------------
%%% Exports
%%--------------------------------------------------------------------
destroy(Ref) when is_pid(Ref) ->
    gen_server:call(Ref, destroy).

start_link(Opt) when is_list(Opt) ->
    Fun = ?PROPLIST_TO_RECORD(state),
    State = Fun(Opt),
    gen_server:start_link(?MODULE, [State], []).


%%--------------------------------------------------------------------
%%% Callbacks
%%--------------------------------------------------------------------
init([#state{serverv4 = Server,
            clientv4 = Client4,
            clientv6 = Client6,
            ifname = Ifname} = State]) ->
    process_flag(trap_exit, true),

    {ok, FD} = procket:open(0, [
                {protocol, ?IPPROTO_IPV6},
                {type, raw},
                {family, inet}
                ]),

    {ok, Socket} = gen_udp:open(0, [
                binary,
                {fd, FD}
                ]),

    {ok, Dev} = tuncer:create(Ifname, [
                tun,
                no_pi,
                {active, true}
                ]),

    ok = tuncer:up(Dev, Client6),

    {ok, State#state{
            fd = FD,
            s = Socket,
            dev = Dev,
            serverv4 = aton(Server),
            clientv4 = aton(Client4),
            clientv6 = aton(Client6)
            }}.



handle_call(destroy, _From, State) ->
    {stop, normal, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

%%
%% IPv6 encapsuplated packet read from socket
%%
handle_info({udp, Socket, {SA1,SA2,SA3,SA4}, 0,
         <<4:4, HL:4, _ToS:8, _Len:16, _Id:16, 0:1, _DF:1, _MF:1,
           _Off:13, _TTL:8, ?IPPROTO_IPV6:8, _Sum:16,
           SA1:8, SA2:8, SA3:8, SA4:8,
           DA1:8, DA2:8, DA3:8, DA4:8,
           Data/binary>>}, #state{
                s = Socket,
                clientv4 = {DA1,DA2,DA3,DA4},
                serverv4 = {SA1,SA2,SA3,SA4},
                dev = Dev} = State) ->

            Opt = case (HL-5)*4 of
                N when N > 0 -> N;
                _ -> 0
            end,
            <<_:Opt/bits, Payload/bits>> = Data,

            ok = case valid(Payload) of
                true ->
                    tuncer:send(Dev, Payload);
                false ->
                    ok
            end,
            {noreply, State};

% Invalid packet
handle_info({udp, _Socket, Src, 0, Pkt}, State) ->
            error_logger:info_report([
                    {error, invalid_packet},
                    {source_address, Src},
                    {packet, Pkt}
                    ]),
            {noreply, State};

% Data from the tun device
handle_info({tuntap, Dev, Data}, #state{
                dev = Dev,
                s = Socket,
                serverv4 = Server} = State) ->
            ok = gen_udp:send(Socket, Server, 0, Data),
    {noreply, State};

% WTF?
handle_info(Info, State) ->
    error_logger:error_report([wtf, Info]),
    {noreply, State}.

terminate(_Reason, #state{fd = FD}) ->
    procket:close(FD),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
aton(Address) when is_list(Address) ->
    {ok, N} = inet_parse:address(Address),
    N;
aton(Address) when is_tuple(Address) ->
    Address.


% loopback
valid(<<6:4, _Class:8, _Flow:20,
        _Len:16, _Next:8, _Hop:8,
        _SA1:16, _SA2:16, _SA3:16, _SA4:16, _SA5:16, _SA6:16, _SA7:16, _SA8:16,
        0:16, 0:16, 0:16, 0:16, 0:16, 0:16, 0:16, 1:16,
        _Payload/binary>>) ->
    false;
% unspecified address
valid(<<6:4, _Class:8, _Flow:20,
        _Len:16, _Next:8, _Hop:8,
        _SA1:16, _SA2:16, _SA3:16, _SA4:16, _SA5:16, _SA6:16, _SA7:16, _SA8:16,
        0:16, 0:16, 0:16, 0:16, 0:16, 0:16, 0:16, 0:16,
        _Payload/binary>>) ->
    false;
% Multicast 
valid(<<6:4, _Class:8, _Flow:20,
        _Len:16, _Next:8, _Hop:8,
        _SA1:16, _SA2:16, _SA3:16, _SA4:16, _SA5:16, _SA6:16, _SA7:16, _SA8:16,
        16#FF00:16, _:16, _:16, _:16, _:16, _:16, _:16, _:16,
        _Payload/binary>>) ->
    false;
% IPv6 Addresses with Embedded IPv4 Addresses
valid(<<6:4, _Class:8, _Flow:20,
        _Len:16, _Next:8, _Hop:8,
        _SA1:16, _SA2:16, _SA3:16, _SA4:16, _SA5:16, _SA6:16, _SA7:16, _SA8:16,
        0:16, 0:16, 0:16, 0:16, 0:16, 0:16, _:16, _:16,
        _Payload/binary>>) ->
    false;
valid(<<6:4, _Class:8, _Flow:20,
        _Len:16, _Next:8, _Hop:8,
        _SA1:16, _SA2:16, _SA3:16, _SA4:16, _SA5:16, _SA6:16, _SA7:16, _SA8:16,
        0:16, 0:16, 0:16, 0:16, 0:16, 16#FFFF:16, _:16, _:16,
        _Payload/binary>>) ->
    false;
valid(<<6:4, _/binary>>) ->
    true;
% Invalid protocol
valid(_Packet) ->
    false.
