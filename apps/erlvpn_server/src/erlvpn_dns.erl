%%%-------------------------------------------------------------------
%%% @doc ErlVPN DNS Resolver
%%%
%%% Handles DNS queries from tunnel clients. Provides caching
%%% with TTL-based expiration and forwards to configurable
%%% upstream resolvers using OTP's inet_res module.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_dns).

-behaviour(gen_server).

-include_lib("erlvpn_common/include/erlvpn.hrl").
-include_lib("kernel/include/logger.hrl").

%% API
-export([start_link/0, start_link/1,
         resolve/1, resolve/2,
         flush_cache/0, cache_stats/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    upstream   :: [inet:ip_address()],
    cache_max  :: pos_integer(),
    hits = 0   :: non_neg_integer(),
    misses = 0 :: non_neg_integer()
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

%% @doc Resolve a hostname. Type = a | aaaa | mx | cname | ns | soa | txt.
-spec resolve(string() | binary(), atom()) ->
    {ok, [term()]} | {error, term()}.
resolve(Name, Type) when is_binary(Name) ->
    resolve(binary_to_list(Name), Type);
resolve(Name, Type) when is_list(Name) ->
    gen_server:call(?MODULE, {resolve, Name, Type}, 10000).

%% @doc Resolve a raw DNS query binary from a tunnel client.
-spec resolve(binary()) -> {ok, binary()} | {error, term()}.
resolve(QueryBin) when is_binary(QueryBin) ->
    gen_server:call(?MODULE, {resolve_raw, QueryBin}, 10000).

-spec flush_cache() -> ok.
flush_cache() ->
    gen_server:call(?MODULE, flush_cache).

-spec cache_stats() -> map().
cache_stats() ->
    gen_server:call(?MODULE, cache_stats).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Opts) ->
    ets:new(?DNS_CACHE_TABLE, [named_table, set, public,
                               {read_concurrency, true}]),
    UpstreamStrs = proplists:get_value(dns_upstream, Opts,
                       erlvpn_config:get(dns_upstream, ["1.1.1.1", "8.8.8.8"])),
    Upstream = parse_upstream(UpstreamStrs),
    CacheMax = proplists:get_value(dns_cache_size, Opts,
                   erlvpn_config:get(dns_cache_size, 10000)),

    %% Schedule cache cleanup
    erlang:send_after(60000, self(), cleanup_cache),

    ?LOG_INFO(#{msg => "DNS resolver started",
                upstream => UpstreamStrs,
                cache_max => CacheMax}),
    {ok, #state{upstream = Upstream, cache_max = CacheMax}}.

handle_call({resolve, Name, Type}, _From, State) ->
    CacheKey = {Name, Type},
    case cache_lookup(CacheKey) of
        {ok, Result} ->
            erlvpn_metrics:increment(erlvpn_dns_cache_hits_total),
            {reply, {ok, Result}, State#state{hits = State#state.hits + 1}};
        miss ->
            erlvpn_metrics:increment(erlvpn_dns_cache_misses_total),
            erlvpn_metrics:increment(erlvpn_dns_queries_total),
            case do_resolve(Name, Type, State#state.upstream) of
                {ok, Result, TTL} ->
                    cache_store(CacheKey, Result, TTL, State#state.cache_max),
                    {reply, {ok, Result},
                     State#state{misses = State#state.misses + 1}};
                {error, _} = Err ->
                    {reply, Err,
                     State#state{misses = State#state.misses + 1}}
            end
    end;

handle_call({resolve_raw, QueryBin}, _From, State) ->
    erlvpn_metrics:increment(erlvpn_dns_queries_total),
    Result = do_resolve_raw(QueryBin, State#state.upstream),
    {reply, Result, State};

handle_call(flush_cache, _From, State) ->
    ets:delete_all_objects(?DNS_CACHE_TABLE),
    ?LOG_INFO(#{msg => "DNS cache flushed"}),
    {reply, ok, State#state{hits = 0, misses = 0}};

handle_call(cache_stats, _From, State) ->
    Stats = #{size => ets:info(?DNS_CACHE_TABLE, size),
              hits => State#state.hits,
              misses => State#state.misses},
    {reply, Stats, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(cleanup_cache, State) ->
    Now = erlang:system_time(second),
    %% Remove expired entries
    ets:foldl(
        fun({Key, _Result, ExpiresAt}, _) ->
            case ExpiresAt =< Now of
                true -> ets:delete(?DNS_CACHE_TABLE, Key);
                false -> ok
            end
        end, ok, ?DNS_CACHE_TABLE),
    erlang:send_after(60000, self(), cleanup_cache),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%====================================================================
%% Internal
%%====================================================================

do_resolve(Name, Type, _Upstream) ->
    %% Use OTP's inet_res for DNS resolution
    DnsType = normalize_type(Type),
    case inet_res:resolve(Name, in, DnsType, [{timeout, 5000}, {retry, 2}]) of
        {ok, DnsMsg} ->
            Answers = inet_dns:msg(DnsMsg, anlist),
            Records = [inet_dns:rr(RR, data) || RR <- Answers],
            %% Get minimum TTL from answers
            TTLs = [inet_dns:rr(RR, ttl) || RR <- Answers],
            TTL = case TTLs of
                      [] -> 60;
                      _ -> lists:min(TTLs)
                  end,
            {ok, Records, TTL};
        {error, Reason} ->
            ?LOG_DEBUG(#{msg => "DNS resolution failed",
                         name => Name, type => Type, reason => Reason}),
            {error, Reason}
    end.

do_resolve_raw(QueryBin, Upstream) ->
    %% Forward raw DNS query to upstream and return raw response
    case Upstream of
        [Server | _] ->
            case gen_udp:open(0, [binary, {active, false}]) of
                {ok, Socket} ->
                    try
                        ok = gen_udp:send(Socket, Server, 53, QueryBin),
                        case gen_udp:recv(Socket, 0, 5000) of
                            {ok, {_, _, ResponseBin}} ->
                                {ok, ResponseBin};
                            {error, Reason} ->
                                {error, {recv_failed, Reason}}
                        end
                    after
                        gen_udp:close(Socket)
                    end;
                {error, Reason} ->
                    {error, {socket_failed, Reason}}
            end;
        [] ->
            {error, no_upstream_servers}
    end.

cache_lookup(Key) ->
    Now = erlang:system_time(second),
    case ets:lookup(?DNS_CACHE_TABLE, Key) of
        [{_, Result, ExpiresAt}] when ExpiresAt > Now ->
            {ok, Result};
        [{_, _, _}] ->
            %% Expired
            ets:delete(?DNS_CACHE_TABLE, Key),
            miss;
        [] ->
            miss
    end.

cache_store(Key, Result, TTL, MaxSize) ->
    %% Evict if at capacity (simple: just don't insert)
    case ets:info(?DNS_CACHE_TABLE, size) >= MaxSize of
        true ->
            %% Simple eviction: delete first key
            case ets:first(?DNS_CACHE_TABLE) of
                '$end_of_table' -> ok;
                FirstKey -> ets:delete(?DNS_CACHE_TABLE, FirstKey)
            end;
        false ->
            ok
    end,
    ExpiresAt = erlang:system_time(second) + max(TTL, 1),
    ets:insert(?DNS_CACHE_TABLE, {Key, Result, ExpiresAt}).

parse_upstream(Strs) ->
    lists:filtermap(
        fun(Str) ->
            case inet:parse_address(Str) of
                {ok, IP} -> {true, IP};
                _ ->
                    ?LOG_WARNING(#{msg => "Invalid upstream DNS", address => Str}),
                    false
            end
        end, Strs).

normalize_type(a) -> a;
normalize_type(aaaa) -> aaaa;
normalize_type(mx) -> mx;
normalize_type(cname) -> cname;
normalize_type(ns) -> ns;
normalize_type(soa) -> soa;
normalize_type(txt) -> txt;
normalize_type(ptr) -> ptr;
normalize_type(srv) -> srv;
normalize_type(Type) -> Type.
