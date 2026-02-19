%%%-------------------------------------------------------------------
%%% @doc ErlVPN IP Packet Utilities
%%%
%%% Lightweight IP packet parsing for routing decisions.
%%% Extracts version, source/dest IPs, protocol without full
%%% packet decapsulation for maximum performance on the hot path.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_packet).

-export([get_version/1, get_src_ip/1, get_dst_ip/1,
         get_protocol/1, get_header_info/1, is_valid/1,
         ip_to_binary/1, binary_to_ip/1, ip_to_string/1]).

%%====================================================================
%% Types
%%====================================================================

-type ip4() :: {byte(), byte(), byte(), byte()}.
-type ip6() :: {0..65535, 0..65535, 0..65535, 0..65535,
                0..65535, 0..65535, 0..65535, 0..65535}.
-type ip_address() :: ip4() | ip6().

-export_type([ip4/0, ip6/0, ip_address/0]).

%%====================================================================
%% API
%%====================================================================

%% @doc Extract IP version from packet (4 or 6).
-spec get_version(binary()) -> {ok, 4 | 6} | {error, term()}.
get_version(<<4:4, _:4, _/binary>>) -> {ok, 4};
get_version(<<6:4, _:4, _/binary>>) -> {ok, 6};
get_version(<<V:4, _:4, _/binary>>) -> {error, {unsupported_version, V}};
get_version(_) -> {error, truncated}.

%% @doc Extract source IP address from packet.
-spec get_src_ip(binary()) -> {ok, ip_address()} | {error, term()}.
get_src_ip(<<4:4, _:4, _:11/binary, A:8, B:8, C:8, D:8, _/binary>>) ->
    {ok, {A, B, C, D}};
get_src_ip(<<6:4, _:4, _:7/binary,
             S1:16/big, S2:16/big, S3:16/big, S4:16/big,
             S5:16/big, S6:16/big, S7:16/big, S8:16/big,
             _/binary>>) ->
    {ok, {S1, S2, S3, S4, S5, S6, S7, S8}};
get_src_ip(<<V:4, _/bitstring>>) when V =:= 4; V =:= 6 ->
    {error, truncated};
get_src_ip(_) ->
    {error, invalid_packet}.

%% @doc Extract destination IP address from packet.
-spec get_dst_ip(binary()) -> {ok, ip_address()} | {error, term()}.
get_dst_ip(<<4:4, _:4, _:15/binary, A:8, B:8, C:8, D:8, _/binary>>) ->
    {ok, {A, B, C, D}};
get_dst_ip(<<6:4, _:4, _:7/binary,
             _:128,  %% skip source (16 bytes)
             D1:16/big, D2:16/big, D3:16/big, D4:16/big,
             D5:16/big, D6:16/big, D7:16/big, D8:16/big,
             _/binary>>) ->
    {ok, {D1, D2, D3, D4, D5, D6, D7, D8}};
get_dst_ip(<<V:4, _/bitstring>>) when V =:= 4; V =:= 6 ->
    {error, truncated};
get_dst_ip(_) ->
    {error, invalid_packet}.

%% @doc Extract protocol number from packet.
%% For IPv4: protocol field at byte 9.
%% For IPv6: next header field at byte 6.
-spec get_protocol(binary()) -> {ok, non_neg_integer()} | {error, term()}.
get_protocol(<<4:4, _:4, _:8/binary, Proto:8, _/binary>>) ->
    {ok, Proto};
get_protocol(<<6:4, _:4, _:3/binary, _PayloadLen:16/big,
               NextHeader:8, _/binary>>) ->
    {ok, NextHeader};
get_protocol(_) ->
    {error, invalid_packet}.

%% @doc Extract full header info as a map.
-spec get_header_info(binary()) -> {ok, map()} | {error, term()}.
get_header_info(<<4:4, IHL:4, _:8, TotalLen:16/big, _:16,
                  _:16, _TTL:8, Proto:8, _Checksum:16,
                  SA:8, SB:8, SC:8, SD:8,
                  DA:8, DB:8, DC:8, DD:8, _/binary>>) ->
    {ok, #{version => 4,
           ihl => IHL,
           total_length => TotalLen,
           protocol => Proto,
           src_ip => {SA, SB, SC, SD},
           dst_ip => {DA, DB, DC, DD}}};
get_header_info(<<6:4, _TC:8, _FL:20, PayloadLen:16/big,
                  NextHeader:8, _HopLimit:8,
                  S1:16/big, S2:16/big, S3:16/big, S4:16/big,
                  S5:16/big, S6:16/big, S7:16/big, S8:16/big,
                  D1:16/big, D2:16/big, D3:16/big, D4:16/big,
                  D5:16/big, D6:16/big, D7:16/big, D8:16/big,
                  _/binary>>) ->
    {ok, #{version => 6,
           payload_length => PayloadLen,
           protocol => NextHeader,
           src_ip => {S1, S2, S3, S4, S5, S6, S7, S8},
           dst_ip => {D1, D2, D3, D4, D5, D6, D7, D8}}};
get_header_info(_) ->
    {error, invalid_packet}.

%% @doc Basic packet validation.
-spec is_valid(binary()) -> boolean().
is_valid(<<4:4, IHL:4, _:8, TotalLen:16/big, _/binary>> = Pkt) ->
    HeaderLen = IHL * 4,
    byte_size(Pkt) >= HeaderLen andalso
    TotalLen =< byte_size(Pkt) andalso
    HeaderLen >= 20;
is_valid(<<6:4, _:4, _:3/binary, PayloadLen:16/big, _:2/binary,
           _:32/binary, _/binary>> = Pkt) ->
    byte_size(Pkt) >= 40 andalso
    (PayloadLen + 40) =< byte_size(Pkt);
is_valid(_) ->
    false.

%%====================================================================
%% IP Address Conversion
%%====================================================================

%% @doc Convert IP tuple to binary representation.
-spec ip_to_binary(ip_address()) -> binary().
ip_to_binary({A, B, C, D}) ->
    <<A:8, B:8, C:8, D:8>>;
ip_to_binary({S1, S2, S3, S4, S5, S6, S7, S8}) ->
    <<S1:16/big, S2:16/big, S3:16/big, S4:16/big,
      S5:16/big, S6:16/big, S7:16/big, S8:16/big>>.

%% @doc Convert 4 or 16 byte binary to IP tuple.
-spec binary_to_ip(binary()) -> {ok, ip_address()} | {error, term()}.
binary_to_ip(<<A:8, B:8, C:8, D:8>>) ->
    {ok, {A, B, C, D}};
binary_to_ip(<<S1:16/big, S2:16/big, S3:16/big, S4:16/big,
               S5:16/big, S6:16/big, S7:16/big, S8:16/big>>) ->
    {ok, {S1, S2, S3, S4, S5, S6, S7, S8}};
binary_to_ip(_) ->
    {error, invalid_ip_binary}.

%% @doc Convert IP tuple to string.
-spec ip_to_string(ip_address()) -> string().
ip_to_string({A, B, C, D}) ->
    lists:flatten(io_lib:format("~B.~B.~B.~B", [A, B, C, D]));
ip_to_string({S1, S2, S3, S4, S5, S6, S7, S8}) ->
    lists:flatten(io_lib:format("~4.16.0B:~4.16.0B:~4.16.0B:~4.16.0B:"
                                "~4.16.0B:~4.16.0B:~4.16.0B:~4.16.0B",
                                [S1, S2, S3, S4, S5, S6, S7, S8])).
