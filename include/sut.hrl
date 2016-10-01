%% Copyright (c) 2012-2016, Michael Santos <michael.santos@gmail.com>
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
-define(IPPROTO_IPV6, 41).

-define(PROPLIST_TO_RECORD(Record),
        fun(Proplist) ->
            Fields = record_info(fields, Record),
            [Tag| Values] = tuple_to_list(#Record{}),
            Defaults = lists:zip(Fields, Values),
            L = lists:map(fun ({K,V}) -> proplists:get_value(K, Proplist, V) end, Defaults),
            list_to_tuple([Tag|L])
        end).

-record(sut_state, {
        ifname = <<"sut-ipv6">> :: binary(),
        serverv4 = {127,0,0,1} :: string() | inet:ip4_address(),
        clientv4 = {127,0,0,1} :: string() | inet:ip4_address(),
        clientv6 = {0,0,0,0,0,0,0,1} :: string() | inet:ip6_address(),

        filter_out = fun(_Packet, _State) -> ok end :: fun((binary(), #sut_state{}) -> ok | {ok, Packet :: binary()} | {error, any()}),
        filter_in = fun(_Packet, _State) -> ok end :: fun((binary(), #sut_state{}) -> ok | {ok, Packet :: binary()} | {error, any()}),

        error_out = fun(ok) -> ok; (Error) -> Error end :: fun((any()) -> any()),
        error_in = fun(ok) -> ok; (Error) -> Error end :: fun((any()) -> any()),

        s :: undefined | inet:socket(),
        fd :: undefined | integer(),
        dev :: undefined | pid()
        }).
