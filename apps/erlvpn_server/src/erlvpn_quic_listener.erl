%%%-------------------------------------------------------------------
%%% @doc ErlVPN QUIC Listener
%%%
%%% Accepts incoming QUIC connections via quicer and spawns
%%% session processes for each client. Falls back to a disabled
%%% mode when quicer is not available (for testing).
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
    listener   :: reference() | undefined,
    port       :: inet:port_number(),
    enabled    :: boolean(),
    acceptors = [] :: [pid()]
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

handle_info({quic, new_conn, Conn, _Info}, State) ->
    %% New QUIC connection accepted
    handle_new_connection(Conn, State);

handle_info({quic, connected, Conn, _Info}, State) ->
    ?LOG_DEBUG(#{msg => "QUIC connection established", conn => Conn}),
    {noreply, State};

handle_info({quic, new_stream, Stream, #{is_orphan := true} = Info}, State) ->
    %% Orphan stream - need to find or create session for it
    handle_new_stream(Stream, Info, State);

handle_info({quic, shutdown, _Conn, _Info}, State) ->
    ?LOG_INFO(#{msg => "QUIC listener shutdown"}),
    {noreply, State};

handle_info({'DOWN', _Ref, process, Pid, _Reason}, #state{acceptors = Accs} = State) ->
    {noreply, State#state{acceptors = lists:delete(Pid, Accs)}};

handle_info(_Info, State) ->
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
            %% Hand off the connection to the session
            try quicer:handoff(Conn, SessionPid) of
                ok -> ok;
                _ -> ok
            catch _:_ -> ok
            end,
            {noreply, State};
        {error, Reason} ->
            ?LOG_ERROR(#{msg => "Failed to start session",
                         reason => Reason}),
            catch quicer:close_connection(Conn),
            {noreply, State}
    end.

handle_new_stream(Stream, _Info, State) ->
    ?LOG_DEBUG(#{msg => "Orphan stream received", stream => Stream}),
    {noreply, State}.

is_quicer_available() ->
    case code:which(quicer) of
        non_existing -> false;
        _ -> true
    end.
