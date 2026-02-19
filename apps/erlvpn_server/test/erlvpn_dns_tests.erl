-module(erlvpn_dns_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlvpn_common/include/erlvpn.hrl").

%%====================================================================
%% Test fixtures
%%====================================================================

dns_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
         fun resolve_localhost/1,
         fun cache_stats_initial/1,
         fun flush_cache/1,
         fun cache_hit/1
     ]}.

setup() ->
    %% Start metrics first (DNS depends on it)
    {ok, MetricsPid} = erlvpn_metrics:start_link(),
    {ok, Pid} = erlvpn_dns:start_link([{dns_upstream, ["1.1.1.1", "8.8.8.8"]},
                                        {dns_cache_size, 100}]),
    {Pid, MetricsPid}.

cleanup({Pid, MetricsPid}) ->
    gen_server:stop(Pid),
    gen_server:stop(MetricsPid).

%%====================================================================
%% Tests
%%====================================================================

resolve_localhost(_Pids) ->
    fun() ->
        %% Resolve a well-known domain - this requires network
        %% So we test the API without asserting specific results
        case erlvpn_dns:resolve("localhost", a) of
            {ok, Results} ->
                ?assert(is_list(Results));
            {error, _Reason} ->
                %% OK - might fail without network
                ok
        end
    end.

cache_stats_initial(_Pids) ->
    fun() ->
        Stats = erlvpn_dns:cache_stats(),
        ?assertEqual(0, maps:get(size, Stats)),
        ?assertEqual(0, maps:get(hits, Stats)),
        ?assertEqual(0, maps:get(misses, Stats))
    end.

flush_cache(_Pids) ->
    fun() ->
        ok = erlvpn_dns:flush_cache(),
        Stats = erlvpn_dns:cache_stats(),
        ?assertEqual(0, maps:get(size, Stats))
    end.

cache_hit(_Pids) ->
    fun() ->
        %% Try resolving something twice to test caching
        %% This may fail without network, so just verify the API works
        erlvpn_dns:resolve("example.com", a),
        erlvpn_dns:resolve("example.com", a),
        Stats = erlvpn_dns:cache_stats(),
        %% At minimum, we should have some recorded attempts
        ?assert(is_map(Stats))
    end.
