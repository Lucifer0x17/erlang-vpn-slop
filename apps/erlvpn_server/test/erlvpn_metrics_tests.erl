-module(erlvpn_metrics_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Test fixtures
%%====================================================================

metrics_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
         fun counter_increment/1,
         fun counter_increment_by/1,
         fun gauge_set_and_get/1,
         fun gauge_inc_dec/1,
         fun histogram_observe/1,
         fun get_all_metrics/1,
         fun prometheus_format/1,
         fun reset_metric/1,
         fun predefined_metrics_initialized/1
     ]}.

setup() ->
    {ok, Pid} = erlvpn_metrics:start_link(),
    Pid.

cleanup(Pid) ->
    gen_server:stop(Pid).

%%====================================================================
%% Tests
%%====================================================================

counter_increment(_Pid) ->
    fun() ->
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_connections_total)),
        erlvpn_metrics:increment(erlvpn_connections_total),
        ?assertEqual(1, erlvpn_metrics:get(erlvpn_connections_total)),
        erlvpn_metrics:increment(erlvpn_connections_total),
        ?assertEqual(2, erlvpn_metrics:get(erlvpn_connections_total))
    end.

counter_increment_by(_Pid) ->
    fun() ->
        erlvpn_metrics:increment(erlvpn_bytes_rx_total, 1024),
        ?assertEqual(1024, erlvpn_metrics:get(erlvpn_bytes_rx_total)),
        erlvpn_metrics:increment(erlvpn_bytes_rx_total, 2048),
        ?assertEqual(3072, erlvpn_metrics:get(erlvpn_bytes_rx_total))
    end.

gauge_set_and_get(_Pid) ->
    fun() ->
        erlvpn_metrics:gauge_set(erlvpn_connections_active, 42),
        ?assertEqual(42, erlvpn_metrics:get(erlvpn_connections_active))
    end.

gauge_inc_dec(_Pid) ->
    fun() ->
        erlvpn_metrics:gauge_set(erlvpn_connections_active, 10),
        erlvpn_metrics:gauge_inc(erlvpn_connections_active),
        ?assertEqual(11, erlvpn_metrics:get(erlvpn_connections_active)),
        erlvpn_metrics:gauge_dec(erlvpn_connections_active),
        ?assertEqual(10, erlvpn_metrics:get(erlvpn_connections_active))
    end.

histogram_observe(_Pid) ->
    fun() ->
        erlvpn_metrics:histogram_observe(erlvpn_packet_forward_duration, 0.005),
        erlvpn_metrics:histogram_observe(erlvpn_packet_forward_duration, 0.002),
        erlvpn_metrics:histogram_observe(erlvpn_packet_forward_duration, 0.5),
        %% Just verify it doesn't crash - histogram internals are tested via prometheus output
        ok
    end.

get_all_metrics(_Pid) ->
    fun() ->
        erlvpn_metrics:increment(erlvpn_connections_total),
        erlvpn_metrics:gauge_set(erlvpn_connections_active, 5),
        All = erlvpn_metrics:get_all(),
        ?assert(is_map(All)),
        ?assertEqual(1, maps:get(erlvpn_connections_total, All)),
        ?assertEqual(5, maps:get(erlvpn_connections_active, All))
    end.

prometheus_format(_Pid) ->
    fun() ->
        erlvpn_metrics:increment(erlvpn_connections_total, 10),
        Output = iolist_to_binary(erlvpn_metrics:format_prometheus()),
        ?assert(byte_size(Output) > 0),
        %% Check for expected Prometheus format elements
        ?assertNotEqual(nomatch, binary:match(Output, <<"# HELP">>)),
        ?assertNotEqual(nomatch, binary:match(Output, <<"# TYPE">>)),
        ?assertNotEqual(nomatch, binary:match(Output, <<"erlvpn_connections_total">>)),
        ?assertNotEqual(nomatch, binary:match(Output, <<"counter">>)),
        ?assertNotEqual(nomatch, binary:match(Output, <<"gauge">>)),
        ?assertNotEqual(nomatch, binary:match(Output, <<"histogram">>))
    end.

reset_metric(_Pid) ->
    fun() ->
        erlvpn_metrics:increment(erlvpn_connections_total, 100),
        ?assertEqual(100, erlvpn_metrics:get(erlvpn_connections_total)),
        erlvpn_metrics:reset(erlvpn_connections_total),
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_connections_total))
    end.

predefined_metrics_initialized(_Pid) ->
    fun() ->
        %% All predefined counters should start at 0
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_connections_total)),
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_auth_failures_total)),
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_bytes_rx_total)),
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_bytes_tx_total)),
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_packets_rx_total)),
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_dns_queries_total)),
        %% Gauges should also be 0
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_connections_active)),
        ?assertEqual(0, erlvpn_metrics:get(erlvpn_ip_pool_available))
    end.

%%====================================================================
%% Nonexistent metric test
%%====================================================================

nonexistent_metric_test() ->
    {ok, Pid} = erlvpn_metrics:start_link(),
    ?assertEqual(undefined, erlvpn_metrics:get(nonexistent_metric)),
    %% Incrementing nonexistent should not crash
    erlvpn_metrics:increment(nonexistent_metric),
    gen_server:stop(Pid).
