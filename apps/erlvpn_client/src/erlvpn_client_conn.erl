%%%-------------------------------------------------------------------
%%% @doc ErlVPN Client Connection Manager (gen_statem)
%%%
%%% Manages the QUIC connection to the VPN server, including
%%% authentication, configuration, and reconnection logic.
%%% States: disconnected -> connecting -> authenticating -> connected
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_client_conn).

-behaviour(gen_statem).

-include_lib("erlvpn_common/include/erlvpn.hrl").
-include_lib("kernel/include/logger.hrl").

%% API
-export([start_link/0, connect/0, connect/1, disconnect/0,
         status/0, send_packet/1]).

%% gen_statem callbacks
-export([init/1, callback_mode/0, terminate/3]).
-export([disconnected/3, connecting/3, authenticating/3, connected/3]).

-record(data, {
    config         :: #client_config{},
    quic_conn      :: reference() | undefined,
    ctrl_stream    :: reference() | undefined,
    data_stream    :: reference() | undefined,
    tunnel_ip      :: inet:ip4_address() | undefined,
    server_ip      :: inet:ip4_address() | undefined,
    session_token  :: binary() | undefined,
    reconnect_count = 0 :: non_neg_integer(),
    keepalive_ref  :: reference() | undefined,
    buffer = <<>>  :: binary()
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_statem:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec connect() -> ok | {error, term()}.
connect() ->
    connect(#{}).

-spec connect(map()) -> ok | {error, term()}.
connect(Opts) ->
    gen_statem:call(?MODULE, {connect, Opts}).

-spec disconnect() -> ok.
disconnect() ->
    gen_statem:call(?MODULE, disconnect).

-spec status() -> map().
status() ->
    gen_statem:call(?MODULE, status).

-spec send_packet(binary()) -> ok.
send_packet(Packet) ->
    gen_statem:cast(?MODULE, {send_packet, Packet}).

%%====================================================================
%% gen_statem callbacks
%%====================================================================

callback_mode() -> [state_functions, state_enter].

init([]) ->
    Config = load_client_config(),
    {ok, disconnected, #data{config = Config}}.

%%====================================================================
%% State: disconnected
%%====================================================================

disconnected(enter, _OldState, Data) ->
    {keep_state, Data#data{quic_conn = undefined,
                            ctrl_stream = undefined,
                            data_stream = undefined,
                            tunnel_ip = undefined}};

disconnected({call, From}, {connect, Opts}, Data) ->
    Config = maybe_update_config(Data#data.config, Opts),
    {next_state, connecting, Data#data{config = Config, reconnect_count = 0},
     [{reply, From, ok}]};

disconnected({call, From}, disconnect, Data) ->
    {keep_state, Data, [{reply, From, ok}]};

disconnected({call, From}, status, Data) ->
    {keep_state, Data, [{reply, From, #{state => disconnected,
                                         tunnel_ip => undefined}}]};

disconnected(EventType, Event, Data) ->
    handle_common(EventType, Event, disconnected, Data).

%%====================================================================
%% State: connecting
%%====================================================================

connecting(enter, _OldState, #data{config = Config} = Data) ->
    ?LOG_INFO(#{msg => "Connecting to VPN server",
                server => Config#client_config.server_address,
                port => Config#client_config.server_port}),
    %% Attempt QUIC connection
    self() ! do_connect,
    {keep_state, Data, [{state_timeout, 30000, connect_timeout}]};

connecting(info, do_connect, #data{config = Config} = Data) ->
    case try_quic_connect(Config) of
        {ok, Conn, CtrlStream} ->
            ?LOG_INFO(#{msg => "QUIC connection established"}),
            {next_state, authenticating,
             Data#data{quic_conn = Conn, ctrl_stream = CtrlStream}};
        {error, Reason} ->
            ?LOG_WARNING(#{msg => "Connection failed", reason => Reason}),
            maybe_reconnect(Reason, Data)
    end;

connecting(state_timeout, connect_timeout, Data) ->
    ?LOG_WARNING(#{msg => "Connection timeout"}),
    maybe_reconnect(timeout, Data);

connecting({call, From}, disconnect, Data) ->
    {next_state, disconnected, Data, [{reply, From, ok}]};

connecting({call, From}, status, Data) ->
    {keep_state, Data, [{reply, From, #{state => connecting}}]};

connecting(EventType, Event, Data) ->
    handle_common(EventType, Event, connecting, Data).

%%====================================================================
%% State: authenticating
%%====================================================================

authenticating(enter, _OldState, #data{config = Config} = Data) ->
    %% Send auth request
    AuthFrame = case Data#data.session_token of
        undefined ->
            Method = Config#client_config.auth_method,
            Creds = get_credentials(Config),
            erlvpn_protocol:encode_auth_request(Method, Creds);
        Token ->
            erlvpn_protocol:encode_session_resume(Token)
    end,
    ?LOG_INFO(#{msg => "Sending auth frame",
                stream => Data#data.ctrl_stream,
                frame_size => byte_size(AuthFrame)}),
    do_send_control(AuthFrame, Data),
    {keep_state, Data, [{state_timeout, ?AUTH_TIMEOUT_MS, auth_timeout}]};

authenticating(info, {quic_data, _Stream, Bin}, Data) ->
    case erlvpn_protocol:decode_control(Bin) of
        {ok, ?MSG_AUTH_RESPONSE, {ok, SessionToken}, Rest} ->
            ?LOG_INFO(#{msg => "Authentication successful"}),
            {keep_state, Data#data{session_token = SessionToken, buffer = Rest},
             [{next_event, info, check_config}]};
        {ok, ?MSG_AUTH_RESPONSE, {error, Reason}, _} ->
            ?LOG_ERROR(#{msg => "Authentication failed", reason => Reason}),
            {next_state, disconnected, Data};
        {ok, ?MSG_CONFIG_PUSH, Config, _Rest} ->
            handle_config_push(Config, Data);
        {more, _} ->
            {keep_state, Data#data{buffer = Bin}};
        _ ->
            {keep_state, Data}
    end;

authenticating(info, check_config, Data) ->
    %% Wait for config push
    {keep_state, Data};

authenticating(state_timeout, auth_timeout, Data) ->
    ?LOG_WARNING(#{msg => "Authentication timeout"}),
    {next_state, disconnected, Data};

authenticating({call, From}, disconnect, Data) ->
    {next_state, disconnected, Data, [{reply, From, ok}]};

authenticating(EventType, Event, Data) ->
    handle_common(EventType, Event, authenticating, Data).

%%====================================================================
%% State: connected
%%====================================================================

connected(enter, _OldState, Data) ->
    ?LOG_INFO(#{msg => "VPN tunnel active",
                tunnel_ip => Data#data.tunnel_ip}),
    %% Start keepalive timer (25s default)
    KRef = erlang:send_after(25000, self(), send_keepalive),
    %% Notify other client components
    erlvpn_client_forwarder:tunnel_up(Data#data.tunnel_ip, Data#data.data_stream),
    {keep_state, Data#data{keepalive_ref = KRef, reconnect_count = 0}};

connected(info, {quic_data, Stream, Bin}, Data)
  when Stream =:= Data#data.ctrl_stream ->
    handle_control_message(Bin, Data);

connected(info, {quic_data, _Stream, Bin}, Data) ->
    %% Data from server - IP packets
    case erlvpn_protocol:decode_data(Bin) of
        {ok, Packet, _Rest} ->
            erlvpn_client_forwarder:from_server(Packet),
            {keep_state, Data};
        _ ->
            {keep_state, Data}
    end;

connected(info, send_keepalive, Data) ->
    KA = erlvpn_protocol:encode_keepalive(),
    do_send_control(KA, Data),
    KRef = erlang:send_after(25000, self(), send_keepalive),
    {keep_state, Data#data{keepalive_ref = KRef}};

connected(cast, {send_packet, Packet}, Data) ->
    Frame = erlvpn_protocol:encode_data(Packet),
    do_send_data(Frame, Data),
    {keep_state, Data};

connected({call, From}, disconnect, Data) ->
    DisconnectFrame = erlvpn_protocol:encode_disconnect(normal),
    do_send_control(DisconnectFrame, Data),
    erlvpn_client_forwarder:tunnel_down(),
    cancel_keepalive(Data),
    {next_state, disconnected, Data, [{reply, From, ok}]};

connected({call, From}, status, Data) ->
    {keep_state, Data, [{reply, From, #{state => connected,
                                         tunnel_ip => Data#data.tunnel_ip,
                                         server_ip => Data#data.server_ip}}]};

connected(info, {quic_closed, _}, Data) ->
    ?LOG_WARNING(#{msg => "QUIC connection closed"}),
    erlvpn_client_forwarder:tunnel_down(),
    cancel_keepalive(Data),
    maybe_reconnect(connection_closed, Data);

connected(EventType, Event, Data) ->
    handle_common(EventType, Event, connected, Data).

%%====================================================================
%% Terminate
%%====================================================================

terminate(_Reason, _State, Data) ->
    cancel_keepalive(Data),
    ok.

%%====================================================================
%% Internal
%%====================================================================

load_client_config() ->
    #client_config{
        server_address = application:get_env(erlvpn_client, server_address, "127.0.0.1"),
        server_port = application:get_env(erlvpn_client, server_port, 4433),
        transport_mode = application:get_env(erlvpn_client, transport_mode, quic_stream),
        auth_method = application:get_env(erlvpn_client, auth_method, token),
        auth_token = application:get_env(erlvpn_client, auth_token, undefined),
        kill_switch = application:get_env(erlvpn_client, kill_switch, true),
        kill_switch_mode = application:get_env(erlvpn_client, kill_switch_mode, system),
        mtu = application:get_env(erlvpn_client, mtu, 1280),
        reconnect_attempts = application:get_env(erlvpn_client, reconnect_attempts, 10),
        reconnect_backoff_max = application:get_env(erlvpn_client, reconnect_backoff_max, 30000),
        enable_0rtt = application:get_env(erlvpn_client, enable_0rtt, true)
    }.

maybe_update_config(Config, Opts) ->
    Config#client_config{
        server_address = maps:get(server_address, Opts, Config#client_config.server_address),
        server_port = maps:get(server_port, Opts, Config#client_config.server_port),
        auth_token = maps:get(auth_token, Opts, Config#client_config.auth_token)
    }.

get_credentials(#client_config{auth_method = token, auth_token = Token}) ->
    iolist_to_binary([Token]);
get_credentials(#client_config{auth_method = certificate, cert_file = Cert}) ->
    {certificate, Cert};
get_credentials(_) ->
    <<>>.

try_quic_connect(#client_config{server_address = Addr, server_port = Port}) ->
    case is_quicer_available() of
        true ->
            ConnOpts = #{
                alpn => [?ERLVPN_ALPN],
                verify => none,
                idle_timeout_ms => 60000,
                handshake_idle_timeout_ms => ?AUTH_TIMEOUT_MS
            },
            try
                case quicer:connect(Addr, Port, ConnOpts, 10000) of
                    {ok, Conn} ->
                        case quicer:start_stream(Conn, #{active => true}) of
                            {ok, Stream} -> {ok, Conn, Stream};
                            {error, R} -> {error, {stream_failed, R}};
                            {error, R, _} -> {error, {stream_failed, R}}
                        end;
                    {error, Reason} ->
                        {error, Reason};
                    {error, Reason, _Detail} ->
                        {error, Reason}
                end
            catch _:Err -> {error, Err}
            end;
        false ->
            {error, quicer_not_available}
    end.

maybe_reconnect(Reason, #data{config = Config, reconnect_count = Count} = Data) ->
    MaxAttempts = Config#client_config.reconnect_attempts,
    case Count < MaxAttempts of
        true ->
            Delay = min(1000 * (1 bsl Count), Config#client_config.reconnect_backoff_max),
            ?LOG_INFO(#{msg => "Reconnecting",
                        attempt => Count + 1,
                        max => MaxAttempts,
                        delay_ms => Delay,
                        reason => Reason}),
            erlang:send_after(Delay, self(), do_connect),
            {keep_state, Data#data{reconnect_count = Count + 1}};
        false ->
            ?LOG_ERROR(#{msg => "Max reconnect attempts reached"}),
            {next_state, disconnected, Data}
    end.

handle_config_push(Config, Data) when is_map(Config) ->
    TunnelIP = maps:get(tunnel_ip, Config, undefined),
    ServerIP = maps:get(server_ip, Config, undefined),
    ?LOG_INFO(#{msg => "Received config push",
                tunnel_ip => TunnelIP}),
    %% Configure TUN device
    case TunnelIP of
        undefined -> ok;
        _ ->
            erlvpn_client_tun:configure(TunnelIP, maps:get(mtu, Config, 1280)),
            %% Configure DNS
            DnsServers = maps:get(dns_servers, Config, []),
            erlvpn_client_dns:configure(DnsServers)
    end,
    {next_state, connected, Data#data{tunnel_ip = TunnelIP, server_ip = ServerIP}}.

handle_control_message(Bin, Data) ->
    case erlvpn_protocol:decode_control(Bin) of
        {ok, ?MSG_KEEPALIVE, {Timestamp}, _} ->
            Ack = erlvpn_protocol:encode_keepalive_ack(Timestamp),
            do_send_control(Ack, Data),
            {keep_state, Data};
        {ok, ?MSG_KEEPALIVE_ACK, _, _} ->
            {keep_state, Data};
        {ok, ?MSG_DISCONNECT, {Reason}, _} ->
            ?LOG_INFO(#{msg => "Server requested disconnect", reason => Reason}),
            erlvpn_client_forwarder:tunnel_down(),
            {next_state, disconnected, Data};
        {ok, ?MSG_KILL_SWITCH, {Action}, _} ->
            erlvpn_client_killswitch:handle_action(Action),
            {keep_state, Data};
        {ok, ?MSG_ROUTE_UPDATE, {Add, Remove}, _} ->
            erlvpn_client_tun:update_routes(Add, Remove),
            {keep_state, Data};
        _ ->
            {keep_state, Data}
    end.

do_send_control(Frame, #data{ctrl_stream = Stream}) when is_pid(Stream) ->
    catch erlang:send(Stream, {send, Frame}),
    ok;
do_send_control(Frame, #data{ctrl_stream = Stream}) when Stream =/= undefined ->
    Result = try quicer:send(Stream, Frame)
             catch E:R -> {error, {E, R}}
             end,
    ?LOG_INFO(#{msg => "quicer:send ctrl result", result => Result,
                size => byte_size(Frame)}),
    ok;
do_send_control(_, _) -> ok.

do_send_data(Frame, #data{data_stream = Stream}) when is_pid(Stream) ->
    catch erlang:send(Stream, {send, Frame}),
    ok;
do_send_data(Frame, #data{data_stream = Stream}) when Stream =/= undefined ->
    catch quicer:send(Stream, Frame),
    ok;
do_send_data(_, _) -> ok.

cancel_keepalive(#data{keepalive_ref = undefined}) -> ok;
cancel_keepalive(#data{keepalive_ref = Ref}) -> erlang:cancel_timer(Ref).

handle_common(info, {quic, Bin, Stream, _Props}, StateName, Data) when is_binary(Bin) ->
    %% Translate quicer native message format to internal format
    ?LOG_INFO(#{msg => "Client quic data received",
                state => StateName, size => byte_size(Bin)}),
    {keep_state, Data, [{next_event, info, {quic_data, Stream, Bin}}]};
handle_common(info, {quic, closed, _Conn, _Flags}, _StateName, Data) ->
    ?LOG_WARNING(#{msg => "QUIC connection closed"}),
    cancel_keepalive(Data),
    maybe_reconnect(connection_closed, Data);
handle_common(info, {quic, stream_closed, _Stream, _Flags}, _StateName, Data) ->
    {keep_state, Data};
handle_common(info, {quic, peer_send_shutdown, _Stream, _}, _StateName, Data) ->
    {keep_state, Data};
handle_common(info, {quic, EventType, _Handle, _Props}, StateName, _Data) ->
    ?LOG_INFO(#{msg => "Client unhandled quic event",
                state => StateName, quic_event => EventType}),
    {keep_state, _Data};
handle_common({call, From}, status, StateName, Data) ->
    {keep_state, Data, [{reply, From, #{state => StateName}}]};
handle_common(_EventType, _Event, _StateName, Data) ->
    {keep_state, Data}.

is_quicer_available() ->
    case code:which(quicer) of
        non_existing -> false;
        _ -> true
    end.
