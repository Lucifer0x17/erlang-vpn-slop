%%%-------------------------------------------------------------------
%%% @doc ErlVPN Authentication Manager
%%%
%%% Handles client authentication using tokens, certificates,
%%% or passwords. Includes rate limiting per IP address.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_auth).

-behaviour(gen_server).

-include_lib("erlvpn_common/include/erlvpn.hrl").
-include_lib("kernel/include/logger.hrl").

%% API
-export([start_link/0, start_link/1,
         authenticate/2, authenticate/3,
         load_tokens/1, add_token/2, remove_token/1,
         list_clients/0, check_rate_limit/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(RATE_TABLE, erlvpn_rate_limits).
-define(RATE_WINDOW_SECS, 60).

-record(state, {
    auth_method :: atom(),
    max_attempts :: pos_integer()
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

%% @doc Authenticate with method and credentials.
-spec authenticate(atom(), term()) -> {ok, binary()} | {error, term()}.
authenticate(Method, Credentials) ->
    gen_server:call(?MODULE, {authenticate, Method, Credentials, undefined}).

%% @doc Authenticate with rate limiting by client IP.
-spec authenticate(atom(), term(), inet:ip_address() | undefined) ->
    {ok, binary()} | {error, term()}.
authenticate(Method, Credentials, ClientIP) ->
    gen_server:call(?MODULE, {authenticate, Method, Credentials, ClientIP}).

-spec load_tokens(string()) -> ok | {error, term()}.
load_tokens(FilePath) ->
    gen_server:call(?MODULE, {load_tokens, FilePath}).

-spec add_token(binary() | string(), binary() | string()) -> ok.
add_token(Token, ClientId) ->
    gen_server:call(?MODULE, {add_token, to_bin(Token), to_bin(ClientId)}).

-spec remove_token(binary() | string()) -> ok.
remove_token(Token) ->
    gen_server:call(?MODULE, {remove_token, to_bin(Token)}).

-spec list_clients() -> [{binary(), binary()}].
list_clients() ->
    gen_server:call(?MODULE, list_clients).

-spec check_rate_limit(inet:ip_address()) -> ok | {error, rate_limited}.
check_rate_limit(ClientIP) ->
    gen_server:call(?MODULE, {check_rate_limit, ClientIP}).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Opts) ->
    %% Create token storage table
    ets:new(?TOKEN_TABLE, [named_table, set, protected]),
    %% Create rate limit table
    ets:new(?RATE_TABLE, [named_table, set, public]),

    AuthMethod = proplists:get_value(auth_method, Opts,
                     erlvpn_config:get(auth_method, token)),
    MaxAttempts = proplists:get_value(max_auth_attempts, Opts,
                      erlvpn_config:get(max_auth_attempts, ?MAX_AUTH_ATTEMPTS)),

    %% Load tokens from file if configured
    case proplists:get_value(token_file, Opts, erlvpn_config:get(token_file)) of
        undefined -> ok;
        TokenFile -> do_load_tokens(TokenFile)
    end,

    %% Periodic rate limit cleanup
    erlang:send_after(60000, self(), cleanup_rate_limits),

    ?LOG_INFO(#{msg => "Auth manager started",
                method => AuthMethod,
                max_attempts => MaxAttempts}),
    {ok, #state{auth_method = AuthMethod, max_attempts = MaxAttempts}}.

handle_call({authenticate, Method, Credentials, ClientIP}, _From, State) ->
    Result = case maybe_check_rate(ClientIP, State#state.max_attempts) of
        ok ->
            case do_authenticate(Method, Credentials) of
                {ok, ClientId} ->
                    ?LOG_INFO(#{msg => "Authentication successful",
                                client_id => ClientId, method => Method}),
                    {ok, ClientId};
                {error, Reason} = Err ->
                    record_failure(ClientIP),
                    ?LOG_WARNING(#{msg => "Authentication failed",
                                   reason => Reason, method => Method}),
                    Err
            end;
        {error, rate_limited} = Err ->
            ?LOG_WARNING(#{msg => "Rate limited", client_ip => ClientIP}),
            Err
    end,
    {reply, Result, State};

handle_call({load_tokens, FilePath}, _From, State) ->
    Result = do_load_tokens(FilePath),
    {reply, Result, State};

handle_call({add_token, Token, ClientId}, _From, State) ->
    Hash = erlvpn_crypto:hash_token(Token),
    ets:insert(?TOKEN_TABLE, {Hash, ClientId}),
    ?LOG_INFO(#{msg => "Token added", client_id => ClientId}),
    {reply, ok, State};

handle_call({remove_token, Token}, _From, State) ->
    Hash = erlvpn_crypto:hash_token(Token),
    ets:delete(?TOKEN_TABLE, Hash),
    ?LOG_INFO(#{msg => "Token removed"}),
    {reply, ok, State};

handle_call(list_clients, _From, State) ->
    Clients = ets:foldl(
        fun({_Hash, ClientId}, Acc) -> [ClientId | Acc] end,
        [], ?TOKEN_TABLE),
    {reply, Clients, State};

handle_call({check_rate_limit, ClientIP}, _From, State) ->
    Result = maybe_check_rate(ClientIP, State#state.max_attempts),
    {reply, Result, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(cleanup_rate_limits, State) ->
    Now = erlang:system_time(second),
    %% Remove expired rate limit entries
    ets:foldl(
        fun({IP, _Count, FirstAttempt}, _) ->
            case Now - FirstAttempt > ?RATE_WINDOW_SECS of
                true -> ets:delete(?RATE_TABLE, IP);
                false -> ok
            end
        end, ok, ?RATE_TABLE),
    erlang:send_after(60000, self(), cleanup_rate_limits),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%====================================================================
%% Internal
%%====================================================================

do_authenticate(token, Token) when is_binary(Token); is_list(Token) ->
    Hash = erlvpn_crypto:hash_token(Token),
    case ets:lookup(?TOKEN_TABLE, Hash) of
        [{_, ClientId}] -> {ok, ClientId};
        [] -> {error, invalid_token}
    end;
do_authenticate(certificate, _CertInfo) ->
    %% Stub: certificate validation would check against CA
    {error, {not_implemented, certificate}};
do_authenticate(password, {_Username, _Password}) ->
    %% Stub: password validation
    {error, {not_implemented, password}};
do_authenticate(Method, _Credentials) ->
    {error, {unsupported_method, Method}}.

maybe_check_rate(undefined, _MaxAttempts) ->
    ok;
maybe_check_rate(ClientIP, MaxAttempts) ->
    Now = erlang:system_time(second),
    case ets:lookup(?RATE_TABLE, ClientIP) of
        [{_, Count, FirstAttempt}] ->
            case Now - FirstAttempt > ?RATE_WINDOW_SECS of
                true ->
                    %% Window expired, reset
                    ets:delete(?RATE_TABLE, ClientIP),
                    ok;
                false when Count >= MaxAttempts ->
                    {error, rate_limited};
                false ->
                    ok
            end;
        [] ->
            ok
    end.

record_failure(undefined) -> ok;
record_failure(ClientIP) ->
    Now = erlang:system_time(second),
    case ets:lookup(?RATE_TABLE, ClientIP) of
        [{_, Count, FirstAttempt}] ->
            case Now - FirstAttempt > ?RATE_WINDOW_SECS of
                true ->
                    ets:insert(?RATE_TABLE, {ClientIP, 1, Now});
                false ->
                    ets:insert(?RATE_TABLE, {ClientIP, Count + 1, FirstAttempt})
            end;
        [] ->
            ets:insert(?RATE_TABLE, {ClientIP, 1, Now})
    end.

do_load_tokens(FilePath) ->
    case file:read_file(FilePath) of
        {ok, Content} ->
            Lines = binary:split(Content, [<<"\n">>, <<"\r\n">>], [global, trim_all]),
            lists:foreach(
                fun(Line) ->
                    case binary:split(Line, [<<" ">>, <<"\t">>], [trim_all]) of
                        [Token, ClientId] ->
                            Hash = erlvpn_crypto:hash_token(Token),
                            ets:insert(?TOKEN_TABLE, {Hash, ClientId});
                        [_TokenOnly] ->
                            %% Token with no client ID, use hash as ID
                            Hash = erlvpn_crypto:hash_token(Line),
                            ets:insert(?TOKEN_TABLE, {Hash, Line});
                        _ ->
                            ok  %% Skip empty/malformed lines
                    end
                end, Lines),
            ?LOG_INFO(#{msg => "Tokens loaded",
                        file => FilePath,
                        count => ets:info(?TOKEN_TABLE, size)}),
            ok;
        {error, enoent} ->
            ?LOG_WARNING(#{msg => "Token file not found", file => FilePath}),
            {error, {file_not_found, FilePath}};
        {error, Reason} ->
            ?LOG_ERROR(#{msg => "Failed to load tokens",
                         file => FilePath, reason => Reason}),
            {error, Reason}
    end.

to_bin(V) when is_binary(V) -> V;
to_bin(V) when is_list(V) -> list_to_binary(V).
