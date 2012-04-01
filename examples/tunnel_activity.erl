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

%% Flash LED lights on an Arduino
%%
%% Flashes LEDs whenever IPv6 traffic goes through the tunnel.
-module(tunnel_activity).

-export([start/2]).

-define(UINT32(N),  <<(N):4/big-unsigned-integer-unit:8>>).

-define(LEDOUT, 4).
-define(LEDIN, 3).
-define(TIMEOUT, 10).

start(Dev, Opt) ->
    In = proplists:get_value(led_in, Opt, ?LEDIN),
    Out = proplists:get_value(led_out, Opt, ?LEDOUT),

    {ok,FD} = serctl:open(Dev),

    Termios = lists:foldl(
            fun(Fun, Acc) -> Fun(Acc) end,
            serctl:mode(raw),
            [
                fun(N) -> serctl:flow(N, false) end,
                fun(N) -> serctl:ispeed(N, b9600) end,
                fun(N) -> serctl:ospeed(N, b9600) end
                ]
            ),

    ok = serctl:tcsetattr(FD, tcsanow, Termios),

    sut:start([
            {out, fun(_Packet, _State) ->
                        spawn(fun() -> serial_write(FD, Out) end),
                        ok
                end},
            {in, fun(_Packet, _State) ->
                        spawn(fun() -> serial_write(FD, In) end),
                        ok
                end}
            ] ++ Opt).

serial_write(FD, N) ->
    serctl:write(FD, ?UINT32(1 bsl N)),
    receive
    after
        ?TIMEOUT ->
            serctl:write(FD, ?UINT32(0 bsl N))
    end.
