-module(integ_session_lifecycle_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlvpn_common/include/erlvpn.hrl").

%%====================================================================
%% Test fixture
%%====================================================================

session_lifecycle_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
         fun session_starts_in_connecting/1,
         fun auth_request_reaches_active/1,
         fun successful_auth_allocates_and_routes/1,
         fun failed_auth_stays_authenticating/1,
         fun disconnect_cleans_up/1,
         fun keepalive_exchange/1,
         fun get_info_after_auth/1
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

session_starts_in_connecting(_Pids) ->
    fun() ->
        {ok, Pid} = integ_test_helpers:start_session(),
        %% Session should start in connecting state
        {connecting, _Data} = sys:get_state(Pid),
        %% Metrics should be incremented
        ?assertEqual(1, erlvpn_metrics:get(erlvpn_connections_total)),
        ?assertEqual(1, erlvpn_metrics:get(erlvpn_connections_active)),
        erlvpn_session:disconnect(Pid),
        integ_test_helpers:wait_for_process_death(Pid, 2000)
    end.

auth_request_reaches_active(_Pids) ->
    fun() ->
        {ok, Pid} = integ_test_helpers:start_session(),
        %% Send valid auth request
        AuthFrame = erlvpn_protocol:encode_auth_request(token, <<"test_token">>),
        Pid ! {quic_data, self(), AuthFrame},
        timer:sleep(100),
        %% Session should be in active state
        {active, _Data} = sys:get_state(Pid),
        erlvpn_session:disconnect(Pid),
        integ_test_helpers:wait_for_process_death(Pid, 2000)
    end.

successful_auth_allocates_and_routes(_Pids) ->
    fun() ->
        {Pid, TunnelIP, SessionToken} = integ_test_helpers:auth_session_to_active(),
        %% IP should be allocated
        ?assert(TunnelIP =/= undefined),
        ?assertMatch({10, 8, 0, _}, TunnelIP),
        ?assert(erlvpn_ip_pool:is_allocated(TunnelIP)),
        %% Route should be registered
        ?assertMatch({ok, Pid, _}, erlvpn_router:lookup(TunnelIP)),
        ?assertEqual(1, erlvpn_router:route_count()),
        %% Session token should exist
        ?assert(is_binary(SessionToken)),
        ?assert(byte_size(SessionToken) > 0),
        %% Allocated count should be 1
        ?assertEqual(1, erlvpn_ip_pool:allocated_count()),
        erlvpn_session:disconnect(Pid),
        integ_test_helpers:wait_for_process_death(Pid, 2000)
    end.

failed_auth_stays_authenticating(_Pids) ->
    fun() ->
        {ok, Pid} = integ_test_helpers:start_session(),
        %% Send invalid auth request
        AuthFrame = erlvpn_protocol:encode_auth_request(token, <<"bad_token">>),
        Pid ! {quic_data, self(), AuthFrame},
        timer:sleep(100),
        %% Session should still be in authenticating
        {authenticating, _Data} = sys:get_state(Pid),
        %% Should have received error response
        Frames = integ_test_helpers:collect_sent_frames(100),
        Decoded = integ_test_helpers:decode_control_frames(Frames),
        ?assert(lists:any(fun({?MSG_AUTH_RESPONSE, {error, _}}) -> true;
                             (_) -> false end, Decoded)),
        %% Auth failures metric should be incremented
        ?assertEqual(1, erlvpn_metrics:get(erlvpn_auth_failures_total)),
        %% No IP should be allocated
        ?assertEqual(0, erlvpn_ip_pool:allocated_count()),
        ?assertEqual(0, erlvpn_router:route_count()),
        erlvpn_session:disconnect(Pid),
        integ_test_helpers:wait_for_process_death(Pid, 2000)
    end.

disconnect_cleans_up(_Pids) ->
    fun() ->
        {Pid, TunnelIP, _} = integ_test_helpers:auth_session_to_active(),
        integ_test_helpers:flush_mailbox(),
        %% Verify resources are allocated
        ?assert(erlvpn_ip_pool:is_allocated(TunnelIP)),
        ?assertEqual(1, erlvpn_router:route_count()),
        %% Disconnect
        erlvpn_session:disconnect(Pid),
        ok = integ_test_helpers:wait_for_process_death(Pid, 2000),
        timer:sleep(50),
        %% All resources should be released
        ?assertNot(erlvpn_ip_pool:is_allocated(TunnelIP)),
        ?assertEqual(0, erlvpn_router:route_count()),
        ?assertEqual(0, erlvpn_ip_pool:allocated_count())
    end.

keepalive_exchange(_Pids) ->
    fun() ->
        {Pid, _TunnelIP, _} = integ_test_helpers:auth_session_to_active(),
        integ_test_helpers:flush_mailbox(),
        %% Trigger keepalive from session
        Pid ! send_keepalive,
        timer:sleep(50),
        Frames = integ_test_helpers:collect_sent_frames(100),
        Decoded = integ_test_helpers:decode_control_frames(Frames),
        ?assert(lists:any(fun({?MSG_KEEPALIVE, _}) -> true;
                             (_) -> false end, Decoded)),
        %% Send keepalive from "client" and expect ack
        Timestamp = erlang:system_time(millisecond),
        KAFrame = erlvpn_protocol:encode_keepalive(),
        Pid ! {quic_data, self(), KAFrame},
        timer:sleep(50),
        Frames2 = integ_test_helpers:collect_sent_frames(100),
        Decoded2 = integ_test_helpers:decode_control_frames(Frames2),
        ?assert(lists:any(fun({?MSG_KEEPALIVE_ACK, _}) -> true;
                             (_) -> false end, Decoded2)),
        %% Session should still be active
        {active, _} = sys:get_state(Pid),
        erlvpn_session:disconnect(Pid),
        integ_test_helpers:wait_for_process_death(Pid, 2000),
        _ = Timestamp
    end.

get_info_after_auth(_Pids) ->
    fun() ->
        {Pid, TunnelIP, _} = integ_test_helpers:auth_session_to_active(),
        Info = erlvpn_session:get_info(Pid),
        ?assertMatch(#{session_id := _, client_id := <<"client1">>,
                       tunnel_ip := TunnelIP}, Info),
        ?assert(is_binary(maps:get(session_id, Info))),
        erlvpn_session:disconnect(Pid),
        integ_test_helpers:wait_for_process_death(Pid, 2000)
    end.
