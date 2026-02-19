-module(erlvpn_ip_pool_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Test fixtures - start/stop pool for each test
%%====================================================================

ip_pool_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
         fun allocate_returns_ip/1,
         fun allocate_sequential/1,
         fun release_and_reallocate/1,
         fun allocate_preferred/1,
         fun allocate_preferred_unavailable/1,
         fun is_allocated_check/1,
         fun available_count_decreases/1,
         fun server_ip_is_first/1,
         fun get_range/1,
         fun double_release_error/1
     ]}.

setup() ->
    {ok, Pid} = erlvpn_ip_pool:start_link("10.8.0.0/24"),
    Pid.

cleanup(Pid) ->
    gen_server:stop(Pid).

%%====================================================================
%% Test cases
%%====================================================================

allocate_returns_ip(_Pid) ->
    fun() ->
        {ok, IP} = erlvpn_ip_pool:allocate(),
        ?assertMatch({10, 8, 0, _}, IP),
        %% Should not be the server IP (10.8.0.1)
        ?assertNotEqual({10, 8, 0, 1}, IP)
    end.

allocate_sequential(_Pid) ->
    fun() ->
        {ok, IP1} = erlvpn_ip_pool:allocate(),
        {ok, IP2} = erlvpn_ip_pool:allocate(),
        ?assertNotEqual(IP1, IP2)
    end.

release_and_reallocate(_Pid) ->
    fun() ->
        {ok, IP} = erlvpn_ip_pool:allocate(),
        ?assert(erlvpn_ip_pool:is_allocated(IP)),
        ok = erlvpn_ip_pool:release(IP),
        ?assertNot(erlvpn_ip_pool:is_allocated(IP))
    end.

allocate_preferred(_Pid) ->
    fun() ->
        Preferred = {10, 8, 0, 100},
        {ok, Preferred} = erlvpn_ip_pool:allocate(Preferred),
        ?assert(erlvpn_ip_pool:is_allocated(Preferred))
    end.

allocate_preferred_unavailable(_Pid) ->
    fun() ->
        Preferred = {10, 8, 0, 50},
        {ok, Preferred} = erlvpn_ip_pool:allocate(Preferred),
        %% Try to allocate same IP again
        ?assertEqual({error, unavailable}, erlvpn_ip_pool:allocate(Preferred))
    end.

is_allocated_check(_Pid) ->
    fun() ->
        ?assertNot(erlvpn_ip_pool:is_allocated({10, 8, 0, 200})),
        {ok, {10, 8, 0, 200}} = erlvpn_ip_pool:allocate({10, 8, 0, 200}),
        ?assert(erlvpn_ip_pool:is_allocated({10, 8, 0, 200}))
    end.

available_count_decreases(_Pid) ->
    fun() ->
        Before = erlvpn_ip_pool:available_count(),
        {ok, _} = erlvpn_ip_pool:allocate(),
        After = erlvpn_ip_pool:available_count(),
        ?assertEqual(Before - 1, After),
        ?assertEqual(1, erlvpn_ip_pool:allocated_count())
    end.

server_ip_is_first(_Pid) ->
    fun() ->
        ServerIP = erlvpn_ip_pool:get_server_ip(),
        ?assertEqual({10, 8, 0, 1}, ServerIP)
    end.

get_range(_Pid) ->
    fun() ->
        {First, Last} = erlvpn_ip_pool:get_range(),
        %% /24 network: base=10.8.0.0, first client=10.8.0.2, last=10.8.0.254
        ?assertEqual({10, 8, 0, 2}, First),
        ?assertEqual({10, 8, 0, 254}, Last)
    end.

double_release_error(_Pid) ->
    fun() ->
        ?assertEqual({error, not_allocated},
                     erlvpn_ip_pool:release({10, 8, 0, 200}))
    end.

%%====================================================================
%% Exhaustion test (separate - uses small pool)
%%====================================================================

exhaustion_test() ->
    %% /30 = 4 addresses total. Network + broadcast = 2 reserved.
    %% Server gets .1, so only 1 client IP (.2)
    {ok, Pid} = erlvpn_ip_pool:start_link("10.0.0.0/30"),
    {ok, _IP} = erlvpn_ip_pool:allocate(),
    ?assertEqual({error, exhausted}, erlvpn_ip_pool:allocate()),
    gen_server:stop(Pid).
