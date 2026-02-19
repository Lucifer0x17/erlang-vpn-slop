-module(erlvpn_packet_tests).

-include_lib("eunit/include/eunit.hrl").

%% A minimal valid IPv4 packet (20-byte header, no payload)
%% Version=4, IHL=5, TotalLen=20, Proto=TCP(6), Src=10.8.0.5, Dst=10.8.0.1
-define(IPV4_PKT, <<16#45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0,
                     10, 8, 0, 5, 10, 8, 0, 1>>).

%% A minimal IPv6 packet (40-byte header, no payload)
%% Version=6, PayloadLen=0, NextHeader=TCP(6), HopLimit=64
-define(IPV6_PKT, <<16#60, 0, 0, 0, 0, 0, 6, 64,
                     %% Source: fd00::1
                     16#FD, 16#00, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 1,
                     %% Dest: fd00::2
                     16#FD, 16#00, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 2>>).

%%====================================================================
%% get_version tests
%%====================================================================

get_version_ipv4_test() ->
    ?assertEqual({ok, 4}, erlvpn_packet:get_version(?IPV4_PKT)).

get_version_ipv6_test() ->
    ?assertEqual({ok, 6}, erlvpn_packet:get_version(?IPV6_PKT)).

get_version_truncated_test() ->
    ?assertEqual({error, truncated}, erlvpn_packet:get_version(<<>>)).

get_version_unsupported_test() ->
    ?assertMatch({error, {unsupported_version, _}},
                 erlvpn_packet:get_version(<<16#30, 0, 0>>)).

%%====================================================================
%% get_src_ip tests
%%====================================================================

get_src_ip_v4_test() ->
    ?assertEqual({ok, {10, 8, 0, 5}}, erlvpn_packet:get_src_ip(?IPV4_PKT)).

get_src_ip_v6_test() ->
    ?assertEqual({ok, {16#FD00, 0, 0, 0, 0, 0, 0, 1}},
                 erlvpn_packet:get_src_ip(?IPV6_PKT)).

get_src_ip_truncated_test() ->
    ?assertEqual({error, truncated}, erlvpn_packet:get_src_ip(<<16#45, 0, 0>>)).

%%====================================================================
%% get_dst_ip tests
%%====================================================================

get_dst_ip_v4_test() ->
    ?assertEqual({ok, {10, 8, 0, 1}}, erlvpn_packet:get_dst_ip(?IPV4_PKT)).

get_dst_ip_v6_test() ->
    ?assertEqual({ok, {16#FD00, 0, 0, 0, 0, 0, 0, 2}},
                 erlvpn_packet:get_dst_ip(?IPV6_PKT)).

%%====================================================================
%% get_protocol tests
%%====================================================================

get_protocol_v4_tcp_test() ->
    ?assertEqual({ok, 6}, erlvpn_packet:get_protocol(?IPV4_PKT)).

get_protocol_v6_tcp_test() ->
    ?assertEqual({ok, 6}, erlvpn_packet:get_protocol(?IPV6_PKT)).

get_protocol_invalid_test() ->
    ?assertEqual({error, invalid_packet}, erlvpn_packet:get_protocol(<<>>)).

%%====================================================================
%% get_header_info tests
%%====================================================================

get_header_info_v4_test() ->
    {ok, Info} = erlvpn_packet:get_header_info(?IPV4_PKT),
    ?assertEqual(4, maps:get(version, Info)),
    ?assertEqual(5, maps:get(ihl, Info)),
    ?assertEqual(20, maps:get(total_length, Info)),
    ?assertEqual(6, maps:get(protocol, Info)),
    ?assertEqual({10, 8, 0, 5}, maps:get(src_ip, Info)),
    ?assertEqual({10, 8, 0, 1}, maps:get(dst_ip, Info)).

get_header_info_v6_test() ->
    {ok, Info} = erlvpn_packet:get_header_info(?IPV6_PKT),
    ?assertEqual(6, maps:get(version, Info)),
    ?assertEqual(6, maps:get(protocol, Info)).

get_header_info_invalid_test() ->
    ?assertEqual({error, invalid_packet}, erlvpn_packet:get_header_info(<<1, 2>>)).

%%====================================================================
%% is_valid tests
%%====================================================================

is_valid_ipv4_test() ->
    ?assert(erlvpn_packet:is_valid(?IPV4_PKT)).

is_valid_ipv6_test() ->
    ?assert(erlvpn_packet:is_valid(?IPV6_PKT)).

is_valid_truncated_test() ->
    ?assertNot(erlvpn_packet:is_valid(<<16#45, 0, 0>>)).

is_valid_garbage_test() ->
    ?assertNot(erlvpn_packet:is_valid(<<0, 0, 0, 0>>)).

is_valid_empty_test() ->
    ?assertNot(erlvpn_packet:is_valid(<<>>)).

%%====================================================================
%% IP conversion tests
%%====================================================================

ip_to_binary_v4_test() ->
    ?assertEqual(<<10, 8, 0, 1>>, erlvpn_packet:ip_to_binary({10, 8, 0, 1})).

ip_to_binary_v6_test() ->
    Bin = erlvpn_packet:ip_to_binary({16#FD00, 0, 0, 0, 0, 0, 0, 1}),
    ?assertEqual(16, byte_size(Bin)).

binary_to_ip_v4_test() ->
    ?assertEqual({ok, {10, 8, 0, 1}}, erlvpn_packet:binary_to_ip(<<10, 8, 0, 1>>)).

binary_to_ip_v6_test() ->
    Bin = <<16#FD, 16#00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>,
    {ok, IP} = erlvpn_packet:binary_to_ip(Bin),
    ?assertEqual({16#FD00, 0, 0, 0, 0, 0, 0, 1}, IP).

binary_to_ip_invalid_test() ->
    ?assertEqual({error, invalid_ip_binary}, erlvpn_packet:binary_to_ip(<<1, 2, 3>>)).

ip_roundtrip_v4_test() ->
    IP = {192, 168, 1, 100},
    Bin = erlvpn_packet:ip_to_binary(IP),
    ?assertEqual({ok, IP}, erlvpn_packet:binary_to_ip(Bin)).

ip_to_string_v4_test() ->
    ?assertEqual("10.8.0.1", erlvpn_packet:ip_to_string({10, 8, 0, 1})).
