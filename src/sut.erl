%%% @copyright 2012-2023 Michael Santos <michael.santos@gmail.com>
%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions
%%% are met:
%%%
%%% 1. Redistributions of source code must retain the above copyright notice,
%%% this list of conditions and the following disclaimer.
%%%
%%% 2. Redistributions in binary form must reproduce the above copyright
%%% notice, this list of conditions and the following disclaimer in the
%%% documentation and/or other materials provided with the distribution.
%%%
%%% 3. Neither the name of the copyright holder nor the names of its
%%% contributors may be used to endorse or promote products derived from
%%% this software without specific prior written permission.
%%%
%%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
%%% A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
%%% HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
%%% SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
%%% TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
%%% PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
%%% LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
%%% NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
%%% SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

%% @doc sut, an IPv6 in IPv4 Userlspace Tunnel (RFC 4213)
%%
%% == SETUP ==
%%
%% * Sign up for an IPv6 tunnel with Hurricane Electric
%%
%%   [http://tunnelbroker.net/]
%%
%% * Start the IPv6 tunnel:
%%
%% ```
%%   * Serverv4 = HE IPv4 tunnel end
%%
%%   * Clientv4 = Your local IP address
%%
%%   * Clientv6 = The IPv6 address assigned by HE to your end of the tunnel
%% '''
%%
%% ```
%% sut:start([
%%            {serverv4, "216.66.22.2"},
%%            {clientv4, "192.168.1.72"},
%%            {clientv6, "2001:3:3:3::2"}
%%           ]).
%% '''
%%
%% * Set up MTU and routing (as root)
%%
%% ```
%% ifconfig sut-ipv6 mtu 1480
%% ip route add ::/0 dev sut-ipv6
%% '''
%%
%% * Test the tunnel!
%%
%% ```
%% ping6 ipv6.google.com
%% '''
%%
%% == EXAMPLES ==
%%
%% To compile:
%%
%% ```
%% erlc -I deps -o ebin examples/*.erl
%% '''
%%
%% === basic_firewall ===
%%
%% An example of setting up a stateless packet filter.
%%
%% The rules are:
%%
%% ```
%% * icmp: all
%% * udp: none
%% * tcp:
%%     * outgoing: 22, 80, 443
%%     * incoming: 22
%% '''
%%
%% Start the tunnel with the filter:
%%
%% ```
%% sut:start([
%%     {filter_out, fun(Packet, State) -> basic_firewall:out(Packet, State) end},
%%     {filter_in, fun(Packet, State) -> basic_firewall:in(Packet, State) end},
%%
%%     {serverv4, Server4},
%%     {clientv4, Client4},
%%     {clientv6, Client6}
%%     ]).
%% '''
%%
%% === tunnel_activity ===
%%
%% Flashes LEDs attached to an Arduino to signal tunnel activity. Requires:
%%
%% [https://github.com/msantos/srly]
%%
%% Upload a sketch to the Arduino:
%%
%% [https://github.com/msantos/srly/blob/master/examples/strobe/strobe.pde]
%%
%% Then start the tunnel:
%%
%% ```
%% tunnel_activity:start("/dev/ttyUSB0",
%%         [{led_in, 3},
%%          {led_out, 4},
%%
%%         {serverv4, Server4},
%%         {clientv4, Client4},
%%         {clientv6, Client6}]).
%% '''
-module(sut).
-include("sut.hrl").
-behaviour(gen_server).

-export([
    start/1,
    start_link/1,
    destroy/1
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {
    ifname = <<"sut-ipv6">> :: binary(),
    serverv4 = {127, 0, 0, 1} :: string() | inet:ip4_address(),
    clientv4 = {127, 0, 0, 1} :: string() | inet:ip4_address(),
    clientv6 = {0, 0, 0, 0, 0, 0, 0, 1} :: string() | inet:ip6_address(),

    filter_out = fun(_Packet, _State) -> ok end :: fun(
        (binary(), #sut_state{}) -> ok | {ok, Packet :: binary()} | {error, any()}
    ),
    filter_in = fun(_Packet, _State) -> ok end :: fun(
        (binary(), #sut_state{}) -> ok | {ok, Packet :: binary()} | {error, any()}
    ),

    error_out = fun
        (ok) -> ok;
        (Error) -> Error
    end :: fun((any()) -> any()),
    error_in = fun
        (ok) -> ok;
        (Error) -> Error
    end :: fun((any()) -> any()),

    s :: undefined | inet:socket(),
    fd :: undefined | integer(),
    dev :: undefined | pid()
}).

%%--------------------------------------------------------------------
%%% Exports
%%--------------------------------------------------------------------

%% @doc Shutdown the tunnel. On Linux, the tunnel device will be removed.
-spec destroy(pid()) -> ok.
destroy(Ref) when is_pid(Ref) ->
    gen_server:call(Ref, destroy).

%% @doc Start an IPv6 over IPv4 configured tunnel.
%% @see start_link/1
-spec start(proplists:proplist()) -> 'ignore' | {'error', _} | {'ok', pid()}.
start(Opt) when is_list(Opt) ->
    gen_server:start(?MODULE, [options(Opt)], []).


%% @doc Start an IPv6 over IPv4 configured tunnel.
%%
%% The default tun device is named `sut-ipv6'. To specify the name,
%% use `{ifname, <<"devname">>}'. Note the user running the tunnel
%% must have sudo permissions to configure this device.
%%
%% `{serverv4, Server4}' is the IPv4 address of the peer.
%%
%% `{clientv4, Client4}' is the IPv4 address of the local end. If the
%% client is on a private network (the tunnel will be NAT'ed by
%% the gateway), specify the private IPv4 address here.
%%
%% `{clientv6, Client6}' is the IPv6 address of the local end. This
%% address will usually be assigned by the tunnel broker.
%%
%% `{filter_in, Fun}' allows filtering and arbitrary transformation
%% of IPv6 packets received from the network. All packets undergo
%% the mandatory checks specified by RFC 4213 before being passed
%% to user checks.
%%
%% `{filter_out, Fun}' allows filtering and manipulation of IPv6
%% packets received from the tun device.
%%
%% Filtering functions take 2 arguments: the packet payload (a binary)
%% and the tunnel state:
%%
%% ```
%%     -include("sut.hrl").
%%
%%     -record(sut_state, {
%%         serverv4,
%%         clientv4,
%%         clientv6
%%         }.
%% '''
%%
%% Filtering functions should return `ok' to allow the packet or
%% `{ok, binary()}' if the packet has been altered by the function.
%%
%% Any other return value causes the packet to be dropped. The
%% default filter for both incoming and outgoing packets is a noop:
%%
%% ```
%%     fun(_Packet, _State) -> ok end.
%% '''
-spec start_link(proplists:proplist()) -> 'ignore' | {'error', _} | {'ok', pid()}.
start_link(Opt) when is_list(Opt) ->
    gen_server:start_link(?MODULE, [options(Opt)], []).

%%--------------------------------------------------------------------
%%% Callbacks
%%--------------------------------------------------------------------

%% @private
init([
    #state{
        serverv4 = Server,
        clientv4 = Client4,
        clientv6 = Client6,
        ifname = Ifname
    } = State
]) ->
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

%% @private
handle_call(destroy, _From, State) ->
    {stop, normal, ok, State}.

%% @private
handle_cast(_Msg, State) ->
    {noreply, State}.

%%
%% IPv6 encapsulated packet read from socket
%%
%% @private
handle_info(
    {udp, Socket, {SA1, SA2, SA3, SA4}, 0,
        <<4:4, HL:4, _ToS:8, _Len:16, _Id:16, 0:1, _DF:1, _MF:1, _Off:13, _TTL:8, ?IPPROTO_IPV6:8,
            _Sum:16, SA1:8, SA2:8, SA3:8, SA4:8, DA1:8, DA2:8, DA3:8, DA4:8, Data/binary>>},
    #state{
        s = Socket,
        clientv4 = {DA1, DA2, DA3, DA4},
        serverv4 = {SA1, SA2, SA3, SA4},
        dev = Dev
    } = State
) ->
    Opt =
        case (HL - 5) * 4 of
            N when N > 0 -> N;
            _ -> 0
        end,
    <<_:Opt/bits, Payload/bits>> = Data,

    spawn(sut_fw, in, [Dev, Payload, copy(State)]),
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
handle_info(
    {tuntap, Dev, Data},
    #state{
        dev = Dev,
        s = Socket
    } = State
) ->
    spawn(sut_fw, out, [Socket, Data, copy(State)]),
    {noreply, State};
% WTF?
handle_info(Info, State) ->
    error_logger:error_report([wtf, Info]),
    {noreply, State}.

%% @private
terminate(_Reason, #state{fd = FD}) ->
    procket:close(FD),
    ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
-spec aton(string() | inet:ip_address()) -> inet:ip_address().
aton(Address) when is_list(Address) ->
    {ok, N} = inet_parse:address(Address),
    N;
aton(Address) when is_tuple(Address) ->
    Address.

options(Opt) ->
    Fun = ?PROPLIST_TO_RECORD(state),
    Fun(Opt).

copy(#state{
    serverv4 = Serverv4,
    clientv4 = Clientv4,
    clientv6 = Clientv6,

    filter_out = Fout,
    filter_in = Fin,

    error_out = Eout,
    error_in = Ein
}) ->
    #sut_state{
        serverv4 = Serverv4,
        clientv4 = Clientv4,
        clientv6 = Clientv6,

        filter_out = Fout,
        filter_in = Fin,

        error_out = Eout,
        error_in = Ein
    }.
