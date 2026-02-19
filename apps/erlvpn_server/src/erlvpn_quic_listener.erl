%%%-------------------------------------------------------------------
%%% @doc ErlVPN QUIC Listener
%%%
%%% Accepts incoming QUIC connections via quicer and spawns
%%% session processes for each client. Falls back to a disabled
%%% mode when quicer is not available (for testing).
%%%
%%% Handles the race condition where client-initiated streams
%%% arrive at the listener before controlling_process transfers
%%% ownership to the session. Orphan streams and early data are
%%% forwarded to the most recently spawned session.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_quic_listener).

-behaviour(gen_server).

-include_lib("erlvpn_common/include/erlvpn.hrl").
-include_lib("kernel/include/logger.hrl").

%% API
-export([start_link/0, start_link/1, get_port/0, is_listening/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    listener        :: reference() | undefined,
    port            :: inet:port_number(),
    enabled         :: boolean(),
    acceptors = []  :: [pid()],
    %% Track most recently spawned session to forward orphan streams
    pending_session :: pid() | undefined
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link([]).

-spec start_link(proplists:proplist()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

-spec get_port() -> inet:port_number().
get_port() ->
    gen_server:call(?MODULE, get_port).

-spec is_listening() -> boolean().
is_listening() ->
    gen_server:call(?MODULE, is_listening).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Opts) ->
    Port = proplists:get_value(port, Opts,
               erlvpn_config:get(listen_port, 4433)),
    case is_quicer_available() of
        true ->
            try_start_listener(Port, Opts);
        false ->
            ?LOG_WARNING(#{msg => "quicer not available, QUIC listener disabled",
                           hint => "Install quicer for QUIC transport support"}),
            {ok, #state{port = Port, enabled = false}}
    end.

handle_call(get_port, _From, #state{port = Port} = State) ->
    {reply, Port, State};

handle_call(is_listening, _From, #state{enabled = En} = State) ->
    {reply, En, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(start_accepting, #state{listener = Listener} = State) ->
    %% Arm the async acceptor — we'll receive {quic, new_conn, ...}
    case quicer:async_accept(Listener, #{}) of
        {ok, Listener} ->
            {noreply, State};
        {error, Reason} ->
            ?LOG_ERROR(#{msg => "Failed to arm acceptor", reason => Reason}),
            {noreply, State}
    end;

handle_info({quic, new_conn, Conn, _Info}, #state{listener = Listener} = State) ->
    %% Complete TLS handshake, then spawn session
    State1 = case quicer:handshake(Conn) of
        {ok, Conn} ->
            handle_new_connection(Conn, State);
        {error, Reason} ->
            ?LOG_WARNING(#{msg => "QUIC handshake failed", reason => Reason}),
            catch quicer:close_connection(Conn),
            State
    end,
    %% Re-arm acceptor for next connection
    catch quicer:async_accept(Listener, #{}),
    {noreply, State1};

handle_info({quic, connected, Conn, _Info}, State) ->
    ?LOG_DEBUG(#{msg => "QUIC connection established", conn => Conn}),
    {noreply, State};

%% Orphan stream: arrived at listener before controlling_process took effect.
%% Forward to the session that was just spawned for this connection.
%% Do NOT clear pending_session — auth data may also be queued behind this.
handle_info({quic, new_stream, Stream, _Flags},
            #state{pending_session = SessionPid} = State)
  when is_pid(SessionPid) ->
    ?LOG_INFO(#{msg => "Forwarding orphan stream to session",
                session => SessionPid, stream => Stream}),
    SessionPid ! {quic, new_stream, Stream, #{}},
    catch quicer:controlling_process(Stream, SessionPid),
    {noreply, State};

handle_info({quic, new_stream, Stream, _Flags}, State) ->
    ?LOG_WARNING(#{msg => "Orphan stream with no pending session",
                   stream => Stream}),
    {noreply, State};

%% Data that arrived at the listener before stream ownership transferred.
%% Forward to pending session.
handle_info({quic, Data, Stream, Props},
            #state{pending_session = SessionPid} = State)
  when is_binary(Data), is_pid(SessionPid) ->
    ?LOG_INFO(#{msg => "Forwarding early stream data to session",
                size => byte_size(Data)}),
    SessionPid ! {quic, Data, Stream, Props},
    {noreply, State};

handle_info({quic, shutdown, _Conn, _Info}, State) ->
    ?LOG_INFO(#{msg => "QUIC listener shutdown"}),
    {noreply, State};

handle_info({quic, listener_stopped, _Listener}, State) ->
    ?LOG_INFO(#{msg => "QUIC listener stopped"}),
    {stop, normal, State};

handle_info({'DOWN', _Ref, process, Pid, _Reason}, #state{acceptors = Accs} = State) ->
    {noreply, State#state{acceptors = lists:delete(Pid, Accs)}};

handle_info(Info, State) ->
    ?LOG_INFO(#{msg => "Listener unhandled message", info => Info}),
    {noreply, State}.

terminate(_Reason, #state{listener = Listener, enabled = true}) ->
    ?LOG_INFO(#{msg => "Stopping QUIC listener"}),
    catch quicer:close_listener(Listener),
    ok;
terminate(_Reason, _State) ->
    ok.

%%====================================================================
%% Internal
%%====================================================================

try_start_listener(Port, Opts) ->
    CertFile = proplists:get_value(cert_file, Opts,
                   erlvpn_config:get(cert_file, "certs/server.crt")),
    KeyFile = proplists:get_value(key_file, Opts,
                  erlvpn_config:get(key_file, "certs/server.key")),

    ListenOpts = #{
        certfile => CertFile,
        keyfile => KeyFile,
        alpn => [?ERLVPN_ALPN],
        peer_unidi_stream_count => 0,
        peer_bidi_stream_count => 10,
        idle_timeout_ms => erlvpn_config:get(keepalive_timeout, 60) * 1000,
        handshake_idle_timeout_ms => ?AUTH_TIMEOUT_MS,
        server_resumption_level => 2  %% Enable 0-RTT
    },

    try
        case quicer:listen(Port, ListenOpts) of
            {ok, Listener} ->
                ?LOG_INFO(#{msg => "QUIC listener started",
                            port => Port,
                            cert => CertFile}),
                %% Start acceptor loop
                self() ! start_accepting,
                {ok, #state{listener = Listener, port = Port, enabled = true}};
            {error, Reason} ->
                ?LOG_ERROR(#{msg => "Failed to start QUIC listener",
                             port => Port, reason => Reason}),
                {ok, #state{port = Port, enabled = false}}
        end
    catch
        Error:Reason2 ->
            ?LOG_ERROR(#{msg => "QUIC listener exception",
                         error => Error, reason => Reason2}),
            {ok, #state{port = Port, enabled = false}}
    end.

handle_new_connection(Conn, State) ->
    %% Spawn a new session process
    case erlvpn_session_sup:start_session(#{quic_conn => Conn}) of
        {ok, SessionPid} ->
            ?LOG_INFO(#{msg => "New client connection",
                        session_pid => SessionPid}),
            %% Transfer connection ownership to the session process
            catch quicer:controlling_process(Conn, SessionPid),
            %% Store session PID to forward any orphan streams/data
            %% that were already queued in our mailbox before the transfer
            State#state{pending_session = SessionPid};
        {error, Reason} ->
            ?LOG_ERROR(#{msg => "Failed to start session",
                         reason => Reason}),
            catch quicer:close_connection(Conn),
            State
    end.

is_quicer_available() ->
    case code:which(quicer) of
        non_existing -> false;
        _ -> true
    end.
