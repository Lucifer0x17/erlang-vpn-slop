-module(integ_client_conn_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlvpn_common/include/erlvpn.hrl").

%%====================================================================
%% Test fixture
%%====================================================================

client_conn_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
         fun starts_in_disconnected/1,
         fun connect_sends_auth_request/1,
         fun auth_and_config_reach_connected/1,
         fun disconnect_from_connected/1,
         fun auth_failure_returns_to_disconnected/1
     ]}.

setup() ->
    %% Create a mock stream process that accumulates {send, Frame} messages
    MockStreamPid = spawn_link(fun() -> mock_stream_loop([]) end),
    %% Mock quicer
    meck:new(quicer, [non_strict]),
    MockConn = make_ref(),
    meck:expect(quicer, connect, fun(_, _, _, _) -> {ok, MockConn} end),
    meck:expect(quicer, start_stream, fun(_, _) -> {ok, MockStreamPid} end),
    meck:expect(quicer, close_connection, fun(_) -> ok end),
    meck:expect(quicer, close_connection, fun(_, _) -> ok end),
    %% Mock client modules
    meck:new(erlvpn_client_tun, [non_strict]),
    meck:expect(erlvpn_client_tun, configure, fun(_, _) -> ok end),
    meck:expect(erlvpn_client_tun, update_routes, fun(_, _) -> ok end),
    meck:new(erlvpn_client_dns, [non_strict]),
    meck:expect(erlvpn_client_dns, configure, fun(_) -> ok end),
    meck:new(erlvpn_client_forwarder, [non_strict]),
    meck:expect(erlvpn_client_forwarder, tunnel_up, fun(_IP, _S) -> ok end),
    meck:expect(erlvpn_client_forwarder, tunnel_down, fun() -> ok end),
    meck:new(erlvpn_client_killswitch, [non_strict]),
    meck:expect(erlvpn_client_killswitch, handle_action, fun(_) -> ok end),
    %% Set application env
    application:set_env(erlvpn_client, auth_token, "test_token_123"),
    application:set_env(erlvpn_client, server_address, "127.0.0.1"),
    application:set_env(erlvpn_client, server_port, 4433),
    %% Start client conn
    {ok, ConnPid} = erlvpn_client_conn:start_link(),
    {ConnPid, MockStreamPid, MockConn}.

cleanup({ConnPid, MockStreamPid, _}) ->
    catch gen_statem:stop(ConnPid),
    MockStreamPid ! stop,
    meck:unload([quicer, erlvpn_client_tun, erlvpn_client_dns,
                 erlvpn_client_forwarder, erlvpn_client_killswitch]).

%%====================================================================
%% Mock stream helper - accumulates frames for later retrieval
%%====================================================================

mock_stream_loop(Acc) ->
    receive
        {send, Frame} ->
            mock_stream_loop(Acc ++ [Frame]);
        {get_frames, From} ->
            From ! {mock_frames, Acc},
            mock_stream_loop([]);
        stop -> ok
    end.

get_mock_frames(MockStreamPid) ->
    MockStreamPid ! {get_frames, self()},
    receive {mock_frames, Frames} -> Frames after 1000 -> [] end.

%%====================================================================
%% Tests
%%====================================================================

starts_in_disconnected({_ConnPid, _, _}) ->
    fun() ->
        Status = erlvpn_client_conn:status(),
        ?assertEqual(disconnected, maps:get(state, Status))
    end.

connect_sends_auth_request({_ConnPid, MockStreamPid, _}) ->
    fun() ->
        %% Trigger connect
        ok = erlvpn_client_conn:connect(),
        timer:sleep(200),
        %% Should have sent an auth request via the mock stream
        Frames = get_mock_frames(MockStreamPid),
        ?assert(length(Frames) > 0),
        AuthFrame = hd(Frames),
        %% Decode the auth request
        {ok, ?MSG_AUTH_REQUEST, {token, Token}, _} =
            erlvpn_protocol:decode_control(AuthFrame),
        ?assertEqual(<<"test_token_123">>, Token)
    end.

auth_and_config_reach_connected({ConnPid, MockStreamPid, _}) ->
    fun() ->
        ok = erlvpn_client_conn:connect(),
        timer:sleep(200),
        %% Consume the auth request frame
        _ = get_mock_frames(MockStreamPid),
        %% Simulate server sending auth response
        AuthResp = erlvpn_protocol:encode_auth_response(ok, <<"session_tok_abc">>),
        ConnPid ! {quic_data, MockStreamPid, AuthResp},
        timer:sleep(50),
        %% Simulate server sending config push
        ConfigPush = erlvpn_protocol:encode_config_push(#{
            tunnel_ip => {10, 8, 0, 5},
            server_ip => {10, 8, 0, 1},
            dns_servers => [{10, 8, 0, 1}],
            routes => ["0.0.0.0/0"],
            mtu => 1280,
            keepalive_interval => 25
        }),
        ConnPid ! {quic_data, MockStreamPid, ConfigPush},
        timer:sleep(200),
        %% Should be connected
        Status = erlvpn_client_conn:status(),
        ?assertEqual(connected, maps:get(state, Status)),
        ?assertEqual({10, 8, 0, 5}, maps:get(tunnel_ip, Status)),
        %% Forwarder should have been notified via meck
        ?assert(meck:called(erlvpn_client_forwarder, tunnel_up, [{10, 8, 0, 5}, '_'])),
        %% TUN should have been configured
        ?assert(meck:called(erlvpn_client_tun, configure, [{10, 8, 0, 5}, 1280])),
        %% DNS should have been configured
        ?assert(meck:called(erlvpn_client_dns, configure, [[{10, 8, 0, 1}]]))
    end.

disconnect_from_connected({ConnPid, MockStreamPid, _}) ->
    fun() ->
        %% Get to connected state
        ok = erlvpn_client_conn:connect(),
        timer:sleep(200),
        _ = get_mock_frames(MockStreamPid),
        AuthResp = erlvpn_protocol:encode_auth_response(ok, <<"tok">>),
        ConnPid ! {quic_data, MockStreamPid, AuthResp},
        timer:sleep(50),
        ConfigPush = erlvpn_protocol:encode_config_push(#{
            tunnel_ip => {10, 8, 0, 5},
            server_ip => {10, 8, 0, 1},
            dns_servers => [],
            routes => [],
            mtu => 1280
        }),
        ConnPid ! {quic_data, MockStreamPid, ConfigPush},
        timer:sleep(200),
        %% Disconnect
        meck:reset(erlvpn_client_forwarder),
        ok = erlvpn_client_conn:disconnect(),
        timer:sleep(100),
        %% Should be disconnected
        Status = erlvpn_client_conn:status(),
        ?assertEqual(disconnected, maps:get(state, Status)),
        %% Should have sent disconnect frame via mock stream
        DisconnectFrames = get_mock_frames(MockStreamPid),
        ?assert(length(DisconnectFrames) > 0),
        [Frame | _] = DisconnectFrames,
        {ok, ?MSG_DISCONNECT, _, _} = erlvpn_protocol:decode_control(Frame),
        %% Forwarder should have been notified
        ?assert(meck:called(erlvpn_client_forwarder, tunnel_down, []))
    end.

auth_failure_returns_to_disconnected({ConnPid, MockStreamPid, _}) ->
    fun() ->
        ok = erlvpn_client_conn:connect(),
        timer:sleep(200),
        _ = get_mock_frames(MockStreamPid),
        %% Send auth failure
        AuthFail = erlvpn_protocol:encode_auth_response(error, invalid_token),
        ConnPid ! {quic_data, MockStreamPid, AuthFail},
        timer:sleep(200),
        %% Should return to disconnected
        Status = erlvpn_client_conn:status(),
        ?assertEqual(disconnected, maps:get(state, Status))
    end.

%%====================================================================
%% Internal helpers
%%====================================================================
