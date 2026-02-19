-module(integ_metrics_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlvpn_common/include/erlvpn.hrl").

%%====================================================================
%% Test fixture
%%====================================================================

metrics_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
         fun counter_persists_after_disconnect/1,
         fun auth_failures_across_sessions/1,
         fun gauge_decrements_on_shutdown/1,
         fun full_lifecycle_metrics/1
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

counter_persists_after_disconnect(_Pids) ->
    fun() ->
        %% Start 3 sessions
        Sessions = lists:map(fun(_) ->
            integ_test_helpers:auth_session_to_active()
        end, lists:seq(1, 3)),
        ?assertEqual(3, erlvpn_metrics:get(erlvpn_connections_total)),
        %% Disconnect all
        lists:foreach(fun({Pid, _, _}) ->
            integ_test_helpers:flush_mailbox(),
            erlvpn_session:disconnect(Pid),
            integ_test_helpers:wait_for_process_death(Pid, 2000)
        end, Sessions),
        timer:sleep(50),
        %% Total counter should persist
        ?assertEqual(3, erlvpn_metrics:get(erlvpn_connections_total)),
        %% Active gauge should be 0
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_connections_active))
    end.

auth_failures_across_sessions(_Pids) ->
    fun() ->
        %% Session 1: 2 bad attempts, then success
        {ok, Pid1} = integ_test_helpers:start_session(),
        BadFrame = erlvpn_protocol:encode_auth_request(token, <<"wrong">>),
        Pid1 ! {quic_data, self(), BadFrame},
        timer:sleep(30),
        Pid1 ! {quic_data, self(), BadFrame},
        timer:sleep(30),
        GoodFrame = erlvpn_protocol:encode_auth_request(token, <<"test_token">>),
        Pid1 ! {quic_data, self(), GoodFrame},
        timer:sleep(100),
        integ_test_helpers:flush_mailbox(),
        %% Session 2: 2 bad attempts, then success
        {ok, Pid2} = integ_test_helpers:start_session(),
        Pid2 ! {quic_data, self(), BadFrame},
        timer:sleep(30),
        Pid2 ! {quic_data, self(), BadFrame},
        timer:sleep(30),
        Pid2 ! {quic_data, self(), GoodFrame},
        timer:sleep(100),
        integ_test_helpers:flush_mailbox(),
        %% Total auth failures should be 4
        ?assertEqual(4, erlvpn_metrics:get(erlvpn_auth_failures_total)),
        %% Both sessions should be active
        ?assertEqual(2, erlvpn_metrics:get(erlvpn_connections_active)),
        erlvpn_session:disconnect(Pid1),
        erlvpn_session:disconnect(Pid2),
        integ_test_helpers:wait_for_process_death(Pid1, 2000),
        integ_test_helpers:wait_for_process_death(Pid2, 2000)
    end.

gauge_decrements_on_shutdown(_Pids) ->
    fun() ->
        process_flag(trap_exit, true),
        {Pid, _IP, _} = integ_test_helpers:auth_session_to_active(),
        integ_test_helpers:flush_mailbox(),
        ?assertEqual(1, erlvpn_metrics:get(erlvpn_connections_active)),
        %% Clean shutdown via gen_statem:stop (calls terminate/3)
        ok = gen_statem:stop(Pid, shutdown, 5000),
        timer:sleep(50),
        %% Gauge should be decremented
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_connections_active))
    end.

full_lifecycle_metrics(_Pids) ->
    fun() ->
        %% Fresh server deps from foreach - metrics start at 0
        %% Start 5 sessions
        Sessions = lists:map(fun(_) ->
            integ_test_helpers:auth_session_to_active()
        end, lists:seq(1, 5)),
        ?assertEqual(5, erlvpn_metrics:get(erlvpn_connections_total)),
        ?assertEqual(5, erlvpn_metrics:get(erlvpn_connections_active)),
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_auth_failures_total)),
        %% Disconnect all
        lists:foreach(fun({Pid, _, _}) ->
            integ_test_helpers:flush_mailbox(),
            erlvpn_session:disconnect(Pid),
            integ_test_helpers:wait_for_process_death(Pid, 2000)
        end, Sessions),
        timer:sleep(100),
        ?assertEqual(5, erlvpn_metrics:get(erlvpn_connections_total)),
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_connections_active)),
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_auth_failures_total))
    end.
