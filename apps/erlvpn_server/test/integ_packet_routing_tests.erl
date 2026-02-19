-module(integ_packet_routing_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlvpn_common/include/erlvpn.hrl").

%%====================================================================
%% Test fixture
%%====================================================================

packet_routing_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
         fun client_data_reaches_tun_manager/1,
         fun tunnel_packet_reaches_client/1,
         fun unknown_dest_returns_not_found/1,
         fun invalid_packet_does_not_crash/1,
         fun bidirectional_packet_flow/1
     ]}.

setup() ->
    erlvpn_crypto:init_secret(),
    %% Mock tun_manager - use meck:history to verify calls
    meck:new(erlvpn_tun_manager, [non_strict]),
    meck:expect(erlvpn_tun_manager, start_link, fun() ->
        {ok, spawn_link(fun() -> receive stop -> ok end end)}
    end),
    meck:expect(erlvpn_tun_manager, write_packet, fun(_Pkt) -> ok end),
    {ok, MetPid} = erlvpn_metrics:start_link(),
    {ok, RouterPid} = erlvpn_router:start_link(),
    {ok, PoolPid} = erlvpn_ip_pool:start_link("10.8.0.0/24"),
    {ok, AuthPid} = erlvpn_auth:start_link([{auth_method, token}]),
    ok = erlvpn_auth:add_token(<<"test_token">>, <<"client1">>),
    {MetPid, RouterPid, PoolPid, AuthPid}.

cleanup({MetPid, RouterPid, PoolPid, AuthPid}) ->
    meck:unload(erlvpn_tun_manager),
    lists:foreach(fun(P) -> catch gen_server:stop(P, normal, 1000) end,
                  [AuthPid, PoolPid, RouterPid, MetPid]).

%%====================================================================
%% Helpers - session with separate ctrl/data streams
%%====================================================================

start_data_test_session() ->
    TestPid = self(),
    CtrlCollector = spawn_link(fun() -> ctrl_collector(TestPid) end),
    {ok, Pid} = erlvpn_session:start_link(
        #{quic_conn => make_ref(),
          ctrl_stream => CtrlCollector,
          data_stream => TestPid}),
    AuthFrame = erlvpn_protocol:encode_auth_request(token, <<"test_token">>),
    Pid ! {quic_data, CtrlCollector, AuthFrame},
    timer:sleep(100),
    CtrlCollector ! {get_frames, self()},
    CtrlFrames = receive {ctrl_frames, F} -> F after 1000 -> [] end,
    TunnelIP = extract_tunnel_ip(CtrlFrames),
    {Pid, TunnelIP, CtrlCollector}.

ctrl_collector(TestPid) ->
    ctrl_collector(TestPid, []).

ctrl_collector(TestPid, Acc) ->
    receive
        {send, Frame} ->
            ctrl_collector(TestPid, Acc ++ [Frame]);
        {get_frames, From} ->
            From ! {ctrl_frames, Acc},
            ctrl_collector(TestPid, []);
        stop -> ok
    end.

extract_tunnel_ip([]) -> undefined;
extract_tunnel_ip([Frame | Rest]) ->
    case erlvpn_protocol:decode_control(Frame) of
        {ok, ?MSG_CONFIG_PUSH, Config, _} when is_map(Config) ->
            maps:get(tunnel_ip, Config, undefined);
        _ -> extract_tunnel_ip(Rest)
    end.

%% Extract packets passed to write_packet from meck history
get_tun_write_packets() ->
    History = meck:history(erlvpn_tun_manager),
    [Pkt || {_Pid, {erlvpn_tun_manager, write_packet, [Pkt]}, _Ret} <- History].

%%====================================================================
%% Tests
%%====================================================================

client_data_reaches_tun_manager(_Pids) ->
    fun() ->
        {Pid, TunnelIP, CtrlPid} = start_data_test_session(),
        {active, _} = sys:get_state(Pid),
        meck:reset(erlvpn_tun_manager),
        %% Build a valid IPv4 packet from the tunnel IP to external
        Packet = integ_test_helpers:make_ipv4_packet(TunnelIP, {8, 8, 8, 8}),
        DataFrame = erlvpn_protocol:encode_data(Packet),
        Pid ! {quic_data, self(), DataFrame},
        timer:sleep(200),
        %% Verify tun_manager received the packet via meck history
        WrittenPackets = get_tun_write_packets(),
        ?assert(length(WrittenPackets) > 0),
        ?assertEqual(Packet, hd(WrittenPackets)),
        erlvpn_session:disconnect(Pid),
        integ_test_helpers:wait_for_process_death(Pid, 2000),
        CtrlPid ! stop
    end.

tunnel_packet_reaches_client(_Pids) ->
    fun() ->
        {Pid, TunnelIP, CtrlPid} = start_data_test_session(),
        integ_test_helpers:flush_mailbox(),
        InboundPacket = integ_test_helpers:make_ipv4_packet({8, 8, 8, 8}, TunnelIP),
        ?assertMatch({ok, Pid, _}, erlvpn_router:lookup(TunnelIP)),
        %% Send tunnel_packet to session
        Pid ! {tunnel_packet, InboundPacket},
        timer:sleep(100),
        %% Data frame should arrive at data_stream (self())
        Frames = integ_test_helpers:collect_sent_frames(200),
        ?assert(length(Frames) > 0),
        [DataFrameBin | _] = Frames,
        {ok, DecodedPacket, <<>>} = erlvpn_protocol:decode_data(DataFrameBin),
        ?assertEqual(InboundPacket, DecodedPacket),
        erlvpn_session:disconnect(Pid),
        integ_test_helpers:wait_for_process_death(Pid, 2000),
        CtrlPid ! stop
    end.

unknown_dest_returns_not_found(_Pids) ->
    fun() ->
        ?assertEqual(not_found, erlvpn_router:lookup({10, 8, 0, 250})),
        ?assertEqual(0, erlvpn_router:route_count())
    end.

invalid_packet_does_not_crash(_Pids) ->
    fun() ->
        {Pid, _TunnelIP, CtrlPid} = start_data_test_session(),
        meck:reset(erlvpn_tun_manager),
        InvalidData = <<"not_an_ip_packet">>,
        DataFrame = erlvpn_protocol:encode_data(InvalidData),
        Pid ! {quic_data, self(), DataFrame},
        timer:sleep(200),
        {active, _} = sys:get_state(Pid),
        %% tun_manager should NOT have been called
        ?assertEqual(0, meck:num_calls(erlvpn_tun_manager, write_packet, '_')),
        erlvpn_session:disconnect(Pid),
        integ_test_helpers:wait_for_process_death(Pid, 2000),
        CtrlPid ! stop
    end.

bidirectional_packet_flow(_Pids) ->
    fun() ->
        {Pid, TunnelIP, CtrlPid} = start_data_test_session(),
        integ_test_helpers:flush_mailbox(),
        meck:reset(erlvpn_tun_manager),
        %% Client -> TUN direction
        OutPacket = integ_test_helpers:make_ipv4_packet(TunnelIP, {1, 1, 1, 1}),
        OutFrame = erlvpn_protocol:encode_data(OutPacket),
        Pid ! {quic_data, self(), OutFrame},
        timer:sleep(200),
        WrittenPackets = get_tun_write_packets(),
        ?assert(length(WrittenPackets) > 0),
        ?assertEqual(OutPacket, hd(WrittenPackets)),
        %% TUN -> Client direction
        InPacket = integ_test_helpers:make_ipv4_packet({1, 1, 1, 1}, TunnelIP),
        Pid ! {tunnel_packet, InPacket},
        timer:sleep(100),
        Frames = integ_test_helpers:collect_sent_frames(200),
        ?assert(length(Frames) > 0),
        [InFrame | _] = Frames,
        {ok, InDecoded, <<>>} = erlvpn_protocol:decode_data(InFrame),
        ?assertEqual(InPacket, InDecoded),
        erlvpn_session:disconnect(Pid),
        integ_test_helpers:wait_for_process_death(Pid, 2000),
        CtrlPid ! stop
    end.
