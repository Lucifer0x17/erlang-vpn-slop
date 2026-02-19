%%%-------------------------------------------------------------------
%%% @doc ErlVPN Metrics Collector
%%%
%%% Tracks counters, gauges, and histograms using ETS for
%%% lock-free concurrent updates. Provides Prometheus text
%%% exposition format output.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_metrics).

-behaviour(gen_server).

-include_lib("erlvpn_common/include/erlvpn.hrl").
-include_lib("kernel/include/logger.hrl").

%% API
-export([start_link/0,
         increment/1, increment/2,
         gauge_set/2, gauge_inc/1, gauge_dec/1,
         histogram_observe/2,
         get/1, get_all/0,
         format_prometheus/0, reset/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(HISTOGRAM_BUCKETS, [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 10.0]).

-record(state, {}).

%% Metric definitions: {Name, Type, Help}
-define(METRICS, [
    {erlvpn_connections_active,       gauge,   "Currently connected clients"},
    {erlvpn_connections_total,        counter, "Total connections since start"},
    {erlvpn_auth_failures_total,      counter, "Failed authentication attempts"},
    {erlvpn_bytes_rx_total,           counter, "Total bytes received from clients"},
    {erlvpn_bytes_tx_total,           counter, "Total bytes sent to clients"},
    {erlvpn_packets_rx_total,         counter, "Total packets received"},
    {erlvpn_packets_tx_total,         counter, "Total packets sent"},
    {erlvpn_ip_pool_available,        gauge,   "Available IPs in pool"},
    {erlvpn_dns_queries_total,        counter, "DNS queries handled"},
    {erlvpn_dns_cache_hits_total,     counter, "DNS cache hits"},
    {erlvpn_dns_cache_misses_total,   counter, "DNS cache misses"},
    {erlvpn_quic_0rtt_total,          counter, "Successful 0-RTT resumptions"},
    {erlvpn_packet_forward_duration,  histogram, "Packet forwarding latency in seconds"},
    {erlvpn_session_duration_seconds, histogram, "Session durations in seconds"}
]).

%%====================================================================
%% API
%%====================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Increment a counter by 1.
-spec increment(atom()) -> ok.
increment(Metric) ->
    increment(Metric, 1).

%% @doc Increment a counter by Value.
-spec increment(atom(), non_neg_integer()) -> ok.
increment(Metric, Value) when is_integer(Value), Value >= 0 ->
    try
        ets:update_counter(?METRICS_TABLE, {counter, Metric}, {2, Value})
    catch
        error:badarg -> ok  %% Metric not found, ignore
    end,
    ok.

%% @doc Set a gauge to a specific value.
-spec gauge_set(atom(), number()) -> ok.
gauge_set(Metric, Value) ->
    ets:insert(?METRICS_TABLE, {{gauge, Metric}, Value}),
    ok.

%% @doc Increment a gauge by 1.
-spec gauge_inc(atom()) -> ok.
gauge_inc(Metric) ->
    try
        ets:update_counter(?METRICS_TABLE, {gauge, Metric}, {2, 1})
    catch
        error:badarg -> ok
    end,
    ok.

%% @doc Decrement a gauge by 1.
-spec gauge_dec(atom()) -> ok.
gauge_dec(Metric) ->
    try
        ets:update_counter(?METRICS_TABLE, {gauge, Metric}, {2, -1})
    catch
        error:badarg -> ok
    end,
    ok.

%% @doc Record a histogram observation.
-spec histogram_observe(atom(), number()) -> ok.
histogram_observe(Metric, Value) ->
    %% Update sum and count
    try
        ets:update_counter(?METRICS_TABLE, {histogram_count, Metric}, {2, 1}),
        %% Sum is stored as float, need insert
        case ets:lookup(?METRICS_TABLE, {histogram_sum, Metric}) of
            [{_, OldSum}] ->
                ets:insert(?METRICS_TABLE, {{histogram_sum, Metric}, OldSum + Value});
            [] ->
                ets:insert(?METRICS_TABLE, {{histogram_sum, Metric}, Value})
        end,
        %% Update bucket counters
        lists:foreach(
            fun(Bucket) ->
                case Value =< Bucket of
                    true ->
                        ets:update_counter(?METRICS_TABLE,
                            {histogram_bucket, Metric, Bucket}, {2, 1});
                    false ->
                        ok
                end
            end, ?HISTOGRAM_BUCKETS)
    catch
        error:badarg -> ok
    end,
    ok.

%% @doc Get current value of a metric.
-spec get(atom()) -> number() | undefined.
get(Metric) ->
    case ets:lookup(?METRICS_TABLE, {counter, Metric}) of
        [{_, Value}] -> Value;
        [] ->
            case ets:lookup(?METRICS_TABLE, {gauge, Metric}) of
                [{_, Value}] -> Value;
                [] -> undefined
            end
    end.

%% @doc Get all metrics as a map.
-spec get_all() -> map().
get_all() ->
    ets:foldl(
        fun({{counter, Name}, Value}, Acc) ->
                maps:put(Name, Value, Acc);
           ({{gauge, Name}, Value}, Acc) ->
                maps:put(Name, Value, Acc);
           (_, Acc) ->
                Acc
        end, #{}, ?METRICS_TABLE).

%% @doc Format all metrics as Prometheus text exposition format.
-spec format_prometheus() -> iolist().
format_prometheus() ->
    lists:flatmap(fun format_metric/1, ?METRICS).

%% @doc Reset a metric to zero.
-spec reset(atom()) -> ok.
reset(Metric) ->
    ets:insert(?METRICS_TABLE, {{counter, Metric}, 0}),
    ets:insert(?METRICS_TABLE, {{gauge, Metric}, 0}),
    ok.

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    ets:new(?METRICS_TABLE, [named_table, public, set,
                             {write_concurrency, true},
                             {read_concurrency, true}]),
    %% Initialize all metrics
    lists:foreach(fun init_metric/1, ?METRICS),
    ?LOG_INFO(#{msg => "Metrics collector started"}),
    {ok, #state{}}.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%====================================================================
%% Internal
%%====================================================================

init_metric({Name, counter, _Help}) ->
    ets:insert(?METRICS_TABLE, {{counter, Name}, 0});
init_metric({Name, gauge, _Help}) ->
    ets:insert(?METRICS_TABLE, {{gauge, Name}, 0});
init_metric({Name, histogram, _Help}) ->
    ets:insert(?METRICS_TABLE, {{histogram_count, Name}, 0}),
    ets:insert(?METRICS_TABLE, {{histogram_sum, Name}, 0.0}),
    lists:foreach(
        fun(Bucket) ->
            ets:insert(?METRICS_TABLE, {{histogram_bucket, Name, Bucket}, 0})
        end, ?HISTOGRAM_BUCKETS).

format_metric({Name, counter, Help}) ->
    NameStr = atom_to_list(Name),
    Value = case ets:lookup(?METRICS_TABLE, {counter, Name}) of
                [{_, V}] -> V;
                [] -> 0
            end,
    [io_lib:format("# HELP ~s ~s\n", [NameStr, Help]),
     io_lib:format("# TYPE ~s counter\n", [NameStr]),
     io_lib:format("~s ~B\n", [NameStr, Value])];

format_metric({Name, gauge, Help}) ->
    NameStr = atom_to_list(Name),
    Value = case ets:lookup(?METRICS_TABLE, {gauge, Name}) of
                [{_, V}] -> V;
                [] -> 0
            end,
    [io_lib:format("# HELP ~s ~s\n", [NameStr, Help]),
     io_lib:format("# TYPE ~s gauge\n", [NameStr]),
     io_lib:format("~s ~B\n", [NameStr, Value])];

format_metric({Name, histogram, Help}) ->
    NameStr = atom_to_list(Name),
    Count = case ets:lookup(?METRICS_TABLE, {histogram_count, Name}) of
                [{_, C}] -> C; [] -> 0
            end,
    Sum = case ets:lookup(?METRICS_TABLE, {histogram_sum, Name}) of
              [{_, S}] -> S; [] -> 0.0
          end,
    BucketLines = lists:map(
        fun(Bucket) ->
            BCount = case ets:lookup(?METRICS_TABLE, {histogram_bucket, Name, Bucket}) of
                         [{_, BC}] -> BC; [] -> 0
                     end,
            io_lib:format("~s_bucket{le=\"~.3f\"} ~B\n", [NameStr, Bucket, BCount])
        end, ?HISTOGRAM_BUCKETS),
    [io_lib:format("# HELP ~s ~s\n", [NameStr, Help]),
     io_lib:format("# TYPE ~s histogram\n", [NameStr]),
     BucketLines,
     io_lib:format("~s_bucket{le=\"+Inf\"} ~B\n", [NameStr, Count]),
     io_lib:format("~s_sum ~.6f\n", [NameStr, Sum]),
     io_lib:format("~s_count ~B\n", [NameStr, Count])].
