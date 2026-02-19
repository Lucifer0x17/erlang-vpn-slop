-module(integ_test_helpers).

-include_lib("erlvpn_common/include/erlvpn.hrl").

-export([start_server_deps/0, stop_server_deps/1,
         start_session/0, start_session/1,
         auth_session_to_active/0, auth_session_to_active/1,
         make_ipv4_packet/2,
         collect_sent_frames/0, collect_sent_frames/1,
         decode_control_frames/1,
         flush_mailbox/0, wait_for_process_death/2]).

%%====================================================================
%% Server dependency management
%%====================================================================

start_server_deps() ->
    start_server_deps("10.8.0.0/24").

start_server_deps(CIDR) ->
    erlvpn_crypto:init_secret(),
    {ok, MetPid} = erlvpn_metrics:start_link(),
    {ok, RouterPid} = erlvpn_router:start_link(),
    {ok, PoolPid} = erlvpn_ip_pool:start_link(CIDR),
    {ok, AuthPid} = erlvpn_auth:start_link([{auth_method, token}]),
    {ok, TunPid} = erlvpn_tun_manager:start_link(),
    [MetPid, RouterPid, PoolPid, AuthPid, TunPid].

stop_server_deps(Pids) ->
    lists:foreach(fun(P) ->
        catch gen_server:stop(P, normal, 1000)
    end, lists:reverse(Pids)).

%%====================================================================
%% Session helpers
%%====================================================================

start_session() ->
    start_session(#{}).

start_session(Overrides) ->
    Conn = maps:get(quic_conn, Overrides, make_ref()),
    Ctrl = maps:get(ctrl_stream, Overrides, self()),
    Data = maps:get(data_stream, Overrides, self()),
    Args = #{quic_conn => Conn, ctrl_stream => Ctrl, data_stream => Data},
    erlvpn_session:start_link(Args).

%% Start a session and authenticate it through to active state.
%% Returns {SessionPid, TunnelIP, SessionToken}.
%% The calling process must be the ctrl_stream and data_stream.
auth_session_to_active() ->
    auth_session_to_active(<<"test_token">>).

auth_session_to_active(Token) ->
    {ok, Pid} = start_session(),
    %% Send auth request
    AuthFrame = erlvpn_protocol:encode_auth_request(token, Token),
    Pid ! {quic_data, self(), AuthFrame},
    %% Wait for the session to reach active state
    timer:sleep(50),
    %% Collect response frames
    Frames = collect_sent_frames(200),
    %% Parse out tunnel IP and session token from response frames
    {TunnelIP, SessionToken} = extract_auth_results(Frames),
    {Pid, TunnelIP, SessionToken}.

%%====================================================================
%% Packet construction
%%====================================================================

%% Build a minimal valid 20-byte IPv4 packet
make_ipv4_packet(SrcIP, DstIP) ->
    {SA, SB, SC, SD} = SrcIP,
    {DA, DB, DC, DD} = DstIP,
    TotalLen = 20,
    <<16#45, 0,
      TotalLen:16/big,
      0, 0, 0, 0,
      64, 6,   %% TTL=64, Protocol=TCP
      0, 0,    %% Checksum (0 for test)
      SA, SB, SC, SD,
      DA, DB, DC, DD>>.

%%====================================================================
%% Message collection
%%====================================================================

collect_sent_frames() ->
    collect_sent_frames(100).

collect_sent_frames(TimeoutMs) ->
    collect_sent_frames_acc(TimeoutMs, []).

collect_sent_frames_acc(TimeoutMs, Acc) ->
    receive
        {send, Frame} ->
            collect_sent_frames_acc(TimeoutMs, [Frame | Acc])
    after TimeoutMs ->
        lists:reverse(Acc)
    end.

%% Decode a list of binary control frames into [{Type, Payload}]
decode_control_frames(Frames) ->
    lists:filtermap(fun(Frame) ->
        case erlvpn_protocol:decode_control(Frame) of
            {ok, Type, Payload, _Rest} -> {true, {Type, Payload}};
            _ -> false
        end
    end, Frames).

%%====================================================================
%% Utility
%%====================================================================

flush_mailbox() ->
    receive _ -> flush_mailbox()
    after 0 -> ok
    end.

wait_for_process_death(Pid, TimeoutMs) ->
    Ref = monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, _Reason} -> ok
    after TimeoutMs ->
        demonitor(Ref, [flush]),
        {error, timeout}
    end.

%%====================================================================
%% Internal
%%====================================================================

extract_auth_results(Frames) ->
    extract_auth_results(Frames, undefined, undefined).

extract_auth_results([], TunnelIP, SessionToken) ->
    {TunnelIP, SessionToken};
extract_auth_results([Frame | Rest], TunnelIP, SessionToken) ->
    case erlvpn_protocol:decode_control(Frame) of
        {ok, ?MSG_AUTH_RESPONSE, {ok, Token}, _} ->
            extract_auth_results(Rest, TunnelIP, Token);
        {ok, ?MSG_CONFIG_PUSH, Config, _} when is_map(Config) ->
            IP = maps:get(tunnel_ip, Config, TunnelIP),
            extract_auth_results(Rest, IP, SessionToken);
        _ ->
            extract_auth_results(Rest, TunnelIP, SessionToken)
    end.
