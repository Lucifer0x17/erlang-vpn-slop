-module(erlvpn_config_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlvpn_common/include/erlvpn.hrl").

%%====================================================================
%% load tests
%%====================================================================

load_defaults_test() ->
    {ok, Config} = erlvpn_config:load(),
    ?assertEqual(4433, Config#server_config.listen_port),
    ?assertEqual(10000, Config#server_config.max_clients),
    ?assertEqual("10.8.0.0/16", Config#server_config.tunnel_ipv4_cidr),
    ?assertEqual(1280, Config#server_config.tunnel_mtu),
    ?assertEqual(25, Config#server_config.keepalive_interval),
    ?assertEqual(60, Config#server_config.keepalive_timeout),
    ?assertEqual(token, Config#server_config.auth_method).

load_with_overrides_test() ->
    {ok, Config} = erlvpn_config:load([{listen_port, 8443}, {max_clients, 500}]),
    ?assertEqual(8443, Config#server_config.listen_port),
    ?assertEqual(500, Config#server_config.max_clients).

load_with_map_overrides_test() ->
    {ok, Config} = erlvpn_config:load(#{listen_port => 9443}),
    ?assertEqual(9443, Config#server_config.listen_port).

load_invalid_port_test() ->
    ?assertMatch({error, _}, erlvpn_config:load([{listen_port, 99999}])).

load_invalid_mtu_test() ->
    ?assertMatch({error, _}, erlvpn_config:load([{tunnel_mtu, 10}])).

load_invalid_cidr_test() ->
    ?assertMatch({error, _}, erlvpn_config:load([{tunnel_ipv4_cidr, "invalid"}])).

%%====================================================================
%% parse_cidr tests
%%====================================================================

parse_cidr_valid_test() ->
    {ok, {{10, 8, 0, 0}, 16}} = erlvpn_config:parse_cidr("10.8.0.0/16"),
    {ok, {{192, 168, 1, 0}, 24}} = erlvpn_config:parse_cidr("192.168.1.0/24"),
    {ok, {{0, 0, 0, 0}, 0}} = erlvpn_config:parse_cidr("0.0.0.0/0").

parse_cidr_invalid_mask_test() ->
    ?assertMatch({error, _}, erlvpn_config:parse_cidr("10.0.0.0/33")).

parse_cidr_invalid_ip_test() ->
    ?assertMatch({error, _}, erlvpn_config:parse_cidr("999.999.999.999/16")).

parse_cidr_no_mask_test() ->
    ?assertMatch({error, _}, erlvpn_config:parse_cidr("10.0.0.0")).

%%====================================================================
%% parse_ip tests
%%====================================================================

parse_ip_v4_test() ->
    ?assertEqual({ok, {127, 0, 0, 1}}, erlvpn_config:parse_ip("127.0.0.1")).

parse_ip_v6_test() ->
    ?assertMatch({ok, _}, erlvpn_config:parse_ip("::1")).

parse_ip_invalid_test() ->
    ?assertMatch({error, _}, erlvpn_config:parse_ip("not_an_ip")).

%%====================================================================
%% to_map tests
%%====================================================================

to_map_test() ->
    {ok, Config} = erlvpn_config:load(),
    Map = erlvpn_config:to_map(Config),
    ?assert(is_map(Map)),
    ?assertEqual(4433, maps:get(listen_port, Map)),
    ?assertEqual(1280, maps:get(tunnel_mtu, Map)).

%%====================================================================
%% validate tests
%%====================================================================

validate_valid_config_test() ->
    {ok, Config} = erlvpn_config:load(),
    ?assertEqual(ok, erlvpn_config:validate(Config)).

validate_invalid_auth_method_test() ->
    {ok, Config} = erlvpn_config:load(),
    BadConfig = Config#server_config{auth_method = invalid_method},
    ?assertMatch({error, _}, erlvpn_config:validate(BadConfig)).
