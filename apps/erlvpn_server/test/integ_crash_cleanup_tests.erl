-module(integ_crash_cleanup_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlvpn_common/include/erlvpn.hrl").

%%====================================================================
%% Test fixture
%%====================================================================

crash_cleanup_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
         fun clean_shutdown_releases_all/1,
         fun kill_cleans_route_but_leaks_ip/1,
         fun crash_during_auth_no_ip_to_clean/1,
         fun multiple_crashes_system_consistent/1
     ]}.

setup() ->
    Pids = integ_test_helpers:start_server_deps(),
    ok = erlvpn_auth:add_token(<<"test_token">>, <<"client1">>),
    Pids.

cleanup(Pids) ->
    integ_test_helpers:stop_server_deps(Pids).

%%====================================================================
%% Tests
%%====================================================================

clean_shutdown_releases_all(_Pids) ->
    fun() ->
        process_flag(trap_exit, true),
        {Pid, TunnelIP, _} = integ_test_helpers:auth_session_to_active(),
        integ_test_helpers:flush_mailbox(),
        %% Verify resources allocated
        ?assert(erlvpn_ip_pool:is_allocated(TunnelIP)),
        ?assertEqual(1, erlvpn_router:route_count()),
        InitActive = erlvpn_metrics:get(erlvpn_connections_active),
        %% Clean shutdown via gen_statem:stop (calls terminate/3)
        ok = gen_statem:stop(Pid, shutdown, 5000),
        timer:sleep(100),
        %% Route cleaned up
        ?assertEqual(0, erlvpn_router:route_count()),
        %% IP released
        ?assertNot(erlvpn_ip_pool:is_allocated(TunnelIP)),
        %% Gauge decremented
        ?assertEqual(InitActive - 1, erlvpn_metrics:get(erlvpn_connections_active))
    end.

kill_cleans_route_but_leaks_ip(_Pids) ->
    fun() ->
        process_flag(trap_exit, true),
        {Pid, TunnelIP, _} = integ_test_helpers:auth_session_to_active(),
        integ_test_helpers:flush_mailbox(),
        ?assert(erlvpn_ip_pool:is_allocated(TunnelIP)),
        ?assertEqual(1, erlvpn_router:route_count()),
        %% Kill signal - terminate/3 does NOT run
        exit(Pid, kill),
        integ_test_helpers:wait_for_process_death(Pid, 2000),
        timer:sleep(200),
        %% Route cleaned by router's DOWN monitor
        ?assertEqual(0, erlvpn_router:route_count()),
        %% IP is LEAKED because terminate/3 never ran
        ?assert(erlvpn_ip_pool:is_allocated(TunnelIP))
    end.

crash_during_auth_no_ip_to_clean(_Pids) ->
    fun() ->
        process_flag(trap_exit, true),
        {ok, Pid} = integ_test_helpers:start_session(),
        %% Session is in connecting - no IP allocated yet
        ?assertEqual(0, erlvpn_ip_pool:allocated_count()),
        ?assertEqual(0, erlvpn_router:route_count()),
        %% Kill it
        exit(Pid, kill),
        integ_test_helpers:wait_for_process_death(Pid, 2000),
        timer:sleep(50),
        %% Nothing to clean up
        ?assertEqual(0, erlvpn_ip_pool:allocated_count()),
        ?assertEqual(0, erlvpn_router:route_count())
    end.

multiple_crashes_system_consistent(_Pids) ->
    fun() ->
        process_flag(trap_exit, true),
        %% Fresh server deps from foreach - metrics start at 0
        %% Start 5 sessions
        Sessions = lists:map(fun(_) ->
            integ_test_helpers:auth_session_to_active()
        end, lists:seq(1, 5)),
        integ_test_helpers:flush_mailbox(),
        ?assertEqual(5, erlvpn_router:route_count()),
        ?assertEqual(5, erlvpn_ip_pool:allocated_count()),
        %% Disconnect 2 normally (terminate runs)
        {P1, _, _} = lists:nth(1, Sessions),
        {P2, _, _} = lists:nth(2, Sessions),
        erlvpn_session:disconnect(P1),
        erlvpn_session:disconnect(P2),
        integ_test_helpers:wait_for_process_death(P1, 2000),
        integ_test_helpers:wait_for_process_death(P2, 2000),
        %% Kill 3 (terminate does NOT run)
        lists:foreach(fun(I) ->
            {P, _, _} = lists:nth(I, Sessions),
            exit(P, kill),
            integ_test_helpers:wait_for_process_death(P, 2000)
        end, [3, 4, 5]),
        timer:sleep(200),
        %% Routes: all cleaned (2 via terminate cleanup, 3 via DOWN monitor)
        ?assertEqual(0, erlvpn_router:route_count()),
        %% IPs: 2 released (normal disconnect), 3 leaked (kill)
        ?assertEqual(3, erlvpn_ip_pool:allocated_count()),
        %% Total connections: always 5
        ?assertEqual(5, erlvpn_metrics:get(erlvpn_connections_total))
    end.
