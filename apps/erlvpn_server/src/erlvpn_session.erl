%%%-------------------------------------------------------------------
%%% @doc ErlVPN Client Session - gen_statem
%%%
%%% Manages the lifecycle of a single VPN client connection.
%%% States: connecting -> authenticating -> active -> disconnecting
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_session).

-behaviour(gen_statem).

-include_lib("erlvpn_common/include/erlvpn.hrl").
-include_lib("kernel/include/logger.hrl").

%% API
-export([start_link/1, send_packet/2, get_info/1, disconnect/1, disconnect/2]).

%% gen_statem callbacks
-export([init/1, callback_mode/0, terminate/3]).
%% State functions
-export([connecting/3, authenticating/3, active/3, disconnecting/3]).

-record(data, {
    session_id    :: binary(),
    quic_conn     :: reference() | undefined,
    ctrl_stream   :: reference() | undefined,
    data_stream   :: reference() | undefined,
    client_id     :: binary() | undefined,
    tunnel_ip     :: inet:ip4_address() | undefined,
    connected_at  :: integer() | undefined,
    last_activity :: integer(),
    auth_attempts = 0 :: non_neg_integer(),
    rx_bytes = 0  :: non_neg_integer(),
    tx_bytes = 0  :: non_neg_integer(),
    rx_packets = 0 :: non_neg_integer(),
    tx_packets = 0 :: non_neg_integer(),
    keepalive_ref :: reference() | undefined,
    buffer = <<>> :: binary()
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Args) ->
    gen_statem:start_link(?MODULE, Args, []).

%% @doc Send a packet to this client.
-spec send_packet(pid(), binary()) -> ok.
send_packet(Pid, Packet) ->
    gen_statem:cast(Pid, {send_packet, Packet}).

%% @doc Get session information.
-spec get_info(pid()) -> map().
get_info(Pid) ->
    gen_statem:call(Pid, get_info).

%% @doc Disconnect a session.
-spec disconnect(pid()) -> ok.
disconnect(Pid) ->
    disconnect(Pid, normal).

-spec disconnect(pid(), atom()) -> ok.
disconnect(Pid, Reason) ->
    gen_statem:cast(Pid, {disconnect, Reason}).

%%====================================================================
%% gen_statem callbacks
%%====================================================================

callback_mode() -> [state_functions, state_enter].

init(#{quic_conn := Conn} = Args) ->
    SessionId = erlvpn_crypto:generate_session_id(),
    CtrlStream = maps:get(ctrl_stream, Args, undefined),
    DataStream = maps:get(data_stream, Args, undefined),
    Now = erlang:monotonic_time(millisecond),
    Data = #data{
        session_id = SessionId,
        quic_conn = Conn,
        ctrl_stream = CtrlStream,
        data_stream = DataStream,
        last_activity = Now
    },
    ?LOG_INFO(#{msg => "Session started",
                session_id => SessionId}),
    erlvpn_metrics:increment(erlvpn_connections_total),
    erlvpn_metrics:gauge_inc(erlvpn_connections_active),
    {ok, connecting, Data}.

%%====================================================================
%% State: connecting
%%====================================================================

connecting(enter, _OldState, Data) ->
    %% Set auth timeout
    {keep_state, Data, [{state_timeout, ?AUTH_TIMEOUT_MS, auth_timeout}]};

connecting(state_timeout, auth_timeout, Data) ->
    ?LOG_WARNING(#{msg => "Auth timeout",
                   session_id => Data#data.session_id}),
    {next_state, disconnecting, Data#data{}, [{next_event, internal, timeout}]};

connecting(info, {ctrl_stream, Stream}, Data) ->
    {next_state, authenticating, Data#data{ctrl_stream = Stream}};

connecting(info, {quic, new_stream, Stream, _Flags}, Data) ->
    ?LOG_INFO(#{msg => "Session received stream",
                session_id => Data#data.session_id, stream => Stream}),
    NewData = case Data#data.ctrl_stream of
        undefined -> Data#data{ctrl_stream = Stream, data_stream = Stream};
        _ -> Data#data{data_stream = Stream}
    end,
    {next_state, authenticating, NewData};

connecting(info, {quic_data, _Stream, Bin}, Data) ->
    ?LOG_INFO(#{msg => "Session received data in connecting",
                session_id => Data#data.session_id,
                size => byte_size(Bin),
                ctrl_stream => Data#data.ctrl_stream}),
    %% Got data before fully connected, buffer it and move to auth
    {next_state, authenticating, Data#data{buffer = Bin}};

connecting(cast, {disconnect, Reason}, Data) ->
    {next_state, disconnecting, Data, [{next_event, internal, Reason}]};

connecting(EventType, Event, Data) ->
    handle_common(EventType, Event, connecting, Data).

%%====================================================================
%% State: authenticating
%%====================================================================

authenticating(enter, _OldState, Data) ->
    %% Process buffered data if any (self-send since next_event
    %% is not allowed from state enter callbacks)
    case Data#data.buffer of
        <<>> -> ok;
        Buf -> self() ! {quic_data, Data#data.ctrl_stream, Buf}
    end,
    {keep_state, Data#data{buffer = <<>>},
     [{state_timeout, ?AUTH_TIMEOUT_MS, auth_timeout}]};

authenticating(state_timeout, auth_timeout, Data) ->
    ?LOG_WARNING(#{msg => "Auth timeout in authenticating state",
                   session_id => Data#data.session_id}),
    {next_state, disconnecting, Data, [{next_event, internal, auth_timeout}]};

authenticating(info, {quic_data, _Stream, Bin}, Data) ->
    case erlvpn_protocol:decode_control(Bin) of
        {ok, ?MSG_AUTH_REQUEST, {Method, Credentials}, _Rest} ->
            handle_auth(Method, Credentials, Data);
        {ok, ?MSG_SESSION_RESUME, {Token}, _Rest} ->
            handle_session_resume(Token, Data);
        {more, _} ->
            %% Need more data, buffer
            {keep_state, Data#data{buffer = Bin}};
        {error, Reason} ->
            ?LOG_WARNING(#{msg => "Invalid auth frame",
                           reason => Reason,
                           session_id => Data#data.session_id}),
            {next_state, disconnecting, Data, [{next_event, internal, protocol_error}]}
    end;

authenticating(cast, {disconnect, Reason}, Data) ->
    {next_state, disconnecting, Data, [{next_event, internal, Reason}]};

authenticating(EventType, Event, Data) ->
    handle_common(EventType, Event, authenticating, Data).

%%====================================================================
%% State: active
%%====================================================================

active(enter, _OldState, Data) ->
    %% Start keepalive timer
    Interval = erlvpn_config:get(keepalive_interval, 25) * 1000,
    Ref = erlang:send_after(Interval, self(), send_keepalive),
    {keep_state, Data#data{keepalive_ref = Ref,
                           connected_at = erlang:monotonic_time(millisecond)}};

active(info, {quic_data, Stream, Bin}, Data) when Stream =:= Data#data.ctrl_stream ->
    %% Control channel message
    handle_control_message(Bin, Data);

active(info, {quic_data, _Stream, Bin}, Data) ->
    %% Data channel - IP packet from client
    handle_data_packet(Bin, Data);

active(info, {tunnel_packet, Packet}, Data) ->
    %% Packet from TUN device destined for this client
    send_to_client(Packet, Data);

active(info, send_keepalive, Data) ->
    KA = erlvpn_protocol:encode_keepalive(),
    do_send_control(KA, Data),
    Interval = erlvpn_config:get(keepalive_interval, 25) * 1000,
    Ref = erlang:send_after(Interval, self(), send_keepalive),
    {keep_state, Data#data{keepalive_ref = Ref}};

active(cast, {send_packet, Packet}, Data) ->
    send_to_client(Packet, Data);

active(cast, {disconnect, Reason}, Data) ->
    {next_state, disconnecting, Data, [{next_event, internal, Reason}]};

active({call, From}, get_info, Data) ->
    Info = #{session_id => Data#data.session_id,
             client_id => Data#data.client_id,
             tunnel_ip => Data#data.tunnel_ip,
             connected_at => Data#data.connected_at,
             rx_bytes => Data#data.rx_bytes,
             tx_bytes => Data#data.tx_bytes,
             rx_packets => Data#data.rx_packets,
             tx_packets => Data#data.tx_packets},
    {keep_state, Data, [{reply, From, Info}]};

active(EventType, Event, Data) ->
    handle_common(EventType, Event, active, Data).

%%====================================================================
%% State: disconnecting
%%====================================================================

disconnecting(enter, _OldState, Data) ->
    %% Cleanup
    cleanup(Data),
    {keep_state, Data, [{state_timeout, 5000, force_stop}]};

disconnecting(internal, Reason, Data) ->
    ?LOG_INFO(#{msg => "Session disconnecting",
                session_id => Data#data.session_id,
                reason => Reason}),
    %% Send disconnect message to client
    DisconnectFrame = erlvpn_protocol:encode_disconnect(Reason),
    do_send_control(DisconnectFrame, Data),
    {stop, normal, Data};

disconnecting(state_timeout, force_stop, Data) ->
    {stop, normal, Data};

disconnecting(EventType, Event, Data) ->
    handle_common(EventType, Event, disconnecting, Data).

%%====================================================================
%% Terminate
%%====================================================================

terminate(Reason, _State, Data) ->
    cleanup(Data),
    ?LOG_INFO(#{msg => "Session terminated",
                session_id => Data#data.session_id,
                reason => Reason}),
    erlvpn_metrics:gauge_dec(erlvpn_connections_active),
    ok.

%%====================================================================
%% Internal
%%====================================================================

handle_auth(Method, Credentials, #data{auth_attempts = Attempts} = Data) ->
    case Attempts >= ?MAX_AUTH_ATTEMPTS of
        true ->
            ?LOG_WARNING(#{msg => "Max auth attempts exceeded",
                           session_id => Data#data.session_id}),
            ErrFrame = erlvpn_protocol:encode_error(?ERR_AUTH_FAILED,
                           <<"Max auth attempts exceeded">>),
            do_send_control(ErrFrame, Data),
            {next_state, disconnecting, Data, [{next_event, internal, auth_exceeded}]};
        false ->
            case erlvpn_auth:authenticate(Method, Credentials) of
                {ok, ClientId} ->
                    setup_tunnel(ClientId, Data);
                {error, Reason} ->
                    erlvpn_metrics:increment(erlvpn_auth_failures_total),
                    ErrFrame = erlvpn_protocol:encode_auth_response(error, Reason),
                    do_send_control(ErrFrame, Data),
                    {keep_state, Data#data{auth_attempts = Attempts + 1}}
            end
    end.

handle_session_resume(Token, Data) ->
    case erlvpn_crypto:validate_session_token(Token) of
        {ok, #{client_id := ClientId, tunnel_ip := IP}} ->
            %% Try to allocate the same IP
            case erlvpn_ip_pool:allocate(IP) of
                {ok, IP} ->
                    finish_setup(ClientId, IP, Data);
                _ ->
                    setup_tunnel(ClientId, Data)
            end;
        {error, Reason} ->
            ?LOG_WARNING(#{msg => "Session resume failed",
                           reason => Reason,
                           session_id => Data#data.session_id}),
            ErrFrame = erlvpn_protocol:encode_auth_response(error, session_expired),
            do_send_control(ErrFrame, Data),
            {keep_state, Data}
    end.

setup_tunnel(ClientId, Data) ->
    case erlvpn_ip_pool:allocate() of
        {ok, TunnelIP} ->
            finish_setup(ClientId, TunnelIP, Data);
        {error, exhausted} ->
            ErrFrame = erlvpn_protocol:encode_error(?ERR_IP_EXHAUSTED,
                           <<"IP pool exhausted">>),
            do_send_control(ErrFrame, Data),
            {next_state, disconnecting, Data, [{next_event, internal, ip_exhausted}]}
    end.

finish_setup(ClientId, TunnelIP, Data) ->
    %% Register route
    erlvpn_router:register_route(TunnelIP, self(), Data#data.data_stream),

    %% Generate session token for future reconnection
    TTL = erlvpn_config:get(session_token_ttl, 86400),
    SessionToken = erlvpn_crypto:generate_session_token(ClientId, TunnelIP, TTL),

    %% Send auth response
    AuthResp = erlvpn_protocol:encode_auth_response(ok, SessionToken),
    do_send_control(AuthResp, Data),

    %% Send config push
    ServerIP = erlvpn_ip_pool:get_server_ip(),
    Config = #{tunnel_ip => TunnelIP,
               server_ip => ServerIP,
               dns_servers => [ServerIP],
               routes => erlvpn_config:get(allowed_ips, ["0.0.0.0/0"]),
               mtu => erlvpn_config:get(tunnel_mtu, 1280),
               keepalive_interval => erlvpn_config:get(keepalive_interval, 25)},
    ConfigFrame = erlvpn_protocol:encode_config_push(Config),
    do_send_control(ConfigFrame, Data),

    ?LOG_INFO(#{msg => "Tunnel established",
                session_id => Data#data.session_id,
                client_id => ClientId,
                tunnel_ip => erlvpn_packet:ip_to_string(TunnelIP)}),

    {next_state, active, Data#data{client_id = ClientId, tunnel_ip = TunnelIP}}.

handle_control_message(Bin, Data) ->
    case erlvpn_protocol:decode_control(Bin) of
        {ok, ?MSG_KEEPALIVE, {Timestamp}, _Rest} ->
            Ack = erlvpn_protocol:encode_keepalive_ack(Timestamp),
            do_send_control(Ack, Data),
            Now = erlang:monotonic_time(millisecond),
            {keep_state, Data#data{last_activity = Now}};
        {ok, ?MSG_KEEPALIVE_ACK, _, _Rest} ->
            Now = erlang:monotonic_time(millisecond),
            {keep_state, Data#data{last_activity = Now}};
        {ok, ?MSG_DISCONNECT, {Reason}, _Rest} ->
            {next_state, disconnecting, Data, [{next_event, internal, Reason}]};
        {ok, _Type, _Payload, _Rest} ->
            {keep_state, Data};
        {more, _} ->
            {keep_state, Data};
        {error, Reason} ->
            ?LOG_WARNING(#{msg => "Invalid control message",
                           reason => Reason,
                           session_id => Data#data.session_id}),
            {keep_state, Data}
    end.

handle_data_packet(Bin, Data) ->
    case erlvpn_protocol:decode_data(Bin) of
        {ok, Packet, Rest} ->
            %% Validate it's an IP packet
            case erlvpn_packet:is_valid(Packet) of
                true ->
                    erlvpn_tun_manager:write_packet(Packet),
                    NewData = Data#data{
                        rx_bytes = Data#data.rx_bytes + byte_size(Packet),
                        rx_packets = Data#data.rx_packets + 1,
                        last_activity = erlang:monotonic_time(millisecond)
                    },
                    %% Process remaining data if any
                    case Rest of
                        <<>> -> {keep_state, NewData};
                        _ -> handle_data_packet(Rest, NewData)
                    end;
                false ->
                    ?LOG_DEBUG(#{msg => "Invalid IP packet from client",
                                 session_id => Data#data.session_id}),
                    {keep_state, Data}
            end;
        {more, _} ->
            {keep_state, Data#data{buffer = Bin}};
        {error, _Reason} ->
            {keep_state, Data}
    end.

send_to_client(Packet, Data) ->
    Frame = erlvpn_protocol:encode_data(Packet),
    do_send_data(Frame, Data),
    NewData = Data#data{
        tx_bytes = Data#data.tx_bytes + byte_size(Packet),
        tx_packets = Data#data.tx_packets + 1
    },
    {keep_state, NewData}.

do_send_control(Frame, #data{ctrl_stream = Stream}) when is_pid(Stream) ->
    catch erlang:send(Stream, {send, Frame}),
    ok;
do_send_control(Frame, #data{ctrl_stream = Stream}) when Stream =/= undefined ->
    catch quicer:send(Stream, Frame),
    ok;
do_send_control(_Frame, _Data) ->
    ok.

do_send_data(Frame, #data{data_stream = Stream}) when is_pid(Stream) ->
    catch erlang:send(Stream, {send, Frame}),
    ok;
do_send_data(Frame, #data{data_stream = Stream}) when Stream =/= undefined ->
    catch quicer:send(Stream, Frame),
    ok;
do_send_data(_Frame, _Data) ->
    ok.

cleanup(#data{tunnel_ip = IP, keepalive_ref = KRef}) ->
    %% Release IP
    case IP of
        undefined -> ok;
        _ ->
            erlvpn_router:unregister_route(IP),
            erlvpn_ip_pool:release(IP)
    end,
    %% Cancel keepalive timer
    case KRef of
        undefined -> ok;
        _ -> erlang:cancel_timer(KRef)
    end,
    ok.

handle_common(info, {quic, Bin, Stream, _Props}, StateName, Data) when is_binary(Bin) ->
    %% Translate quicer native message format to internal format
    ?LOG_INFO(#{msg => "Session quic data received",
                session_id => Data#data.session_id,
                state => StateName,
                size => byte_size(Bin)}),
    {keep_state, Data, [{next_event, info, {quic_data, Stream, Bin}}]};
handle_common(info, {quic, closed, _Conn, _Flags}, _StateName, Data) ->
    ?LOG_WARNING(#{msg => "QUIC connection closed",
                   session_id => Data#data.session_id}),
    {next_state, disconnecting, Data, [{next_event, internal, connection_closed}]};
handle_common(info, {quic, stream_closed, _Stream, _Flags}, _StateName, Data) ->
    {keep_state, Data};
handle_common(info, {quic, peer_send_shutdown, _Stream, _}, _StateName, Data) ->
    {keep_state, Data};
handle_common(info, {quic, new_stream, Stream, _Flags}, StateName, Data) ->
    %% Late stream arrival (after connecting state) — use as data stream
    ?LOG_INFO(#{msg => "Session late stream arrival",
                session_id => Data#data.session_id,
                state => StateName}),
    {keep_state, Data#data{data_stream = Stream}};
handle_common(info, {quic, EventType, _Handle, _Props}, StateName, Data) ->
    ?LOG_INFO(#{msg => "Session unhandled quic event",
                session_id => Data#data.session_id,
                state => StateName,
                quic_event => EventType}),
    {keep_state, Data};
handle_common({call, From}, get_info, _StateName, Data) ->
    Info = #{session_id => Data#data.session_id,
             client_id => Data#data.client_id,
             tunnel_ip => Data#data.tunnel_ip},
    {keep_state, Data, [{reply, From, Info}]};
handle_common(EventType, Event, StateName, Data) ->
    ?LOG_INFO(#{msg => "Session unhandled event",
                session_id => Data#data.session_id,
                state => StateName,
                event_type => EventType,
                event => Event}),
    {keep_state, Data}.
