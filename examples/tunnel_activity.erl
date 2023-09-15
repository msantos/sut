%% @doc Flash LED lights on an Arduino
%%
%% Flashes LEDs whenever IPv6 traffic goes through the tunnel.
-module(tunnel_activity).

-export([start/2]).

-define(UINT32(N), <<(N):4/big-unsigned-integer-unit:8>>).

-define(LEDOUT, 4).
-define(LEDIN, 3).
-define(TIMEOUT, 10).

start(Dev, Opt) ->
    In = proplists:get_value(led_in, Opt, ?LEDIN),
    Out = proplists:get_value(led_out, Opt, ?LEDOUT),

    {ok, FD} = serctl:open(Dev),

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

    sut:start(
        [
            {filter_out, fun(_Packet, _State) ->
                spawn(fun() -> serial_write(FD, Out) end),
                ok
            end},
            {filter_in, fun(_Packet, _State) ->
                spawn(fun() -> serial_write(FD, In) end),
                ok
            end}
        ] ++ Opt
    ).

serial_write(FD, N) ->
    serctl:write(FD, ?UINT32(1 bsl N)),
    receive
    after ?TIMEOUT ->
        serctl:write(FD, ?UINT32(0 bsl N))
    end.
