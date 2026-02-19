-module(prop_erlvpn_packet).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Properties
%%====================================================================

%% Property: ip_to_binary and binary_to_ip are inverses for IPv4
prop_ipv4_roundtrip_test() ->
    ?assert(proper:quickcheck(prop_ipv4_roundtrip(), [{numtests, 500}, noshrink])).

prop_ipv4_roundtrip() ->
    ?FORALL(IP, ipv4_tuple(),
        begin
            Bin = erlvpn_packet:ip_to_binary(IP),
            {ok, IP} =:= erlvpn_packet:binary_to_ip(Bin)
        end).

%% Property: ip_to_binary and binary_to_ip are inverses for IPv6
prop_ipv6_roundtrip_test() ->
    ?assert(proper:quickcheck(prop_ipv6_roundtrip(), [{numtests, 500}, noshrink])).

prop_ipv6_roundtrip() ->
    ?FORALL(IP, ipv6_tuple(),
        begin
            Bin = erlvpn_packet:ip_to_binary(IP),
            {ok, IP} =:= erlvpn_packet:binary_to_ip(Bin)
        end).

%% Property: valid IPv4 packets are recognized as valid
prop_valid_ipv4_detected_test() ->
    ?assert(proper:quickcheck(prop_valid_ipv4_detected(), [{numtests, 200}, noshrink])).

prop_valid_ipv4_detected() ->
    ?FORALL(Pkt, valid_ipv4_packet(),
        erlvpn_packet:is_valid(Pkt) =:= true).

%% Property: get_version returns 4 for valid IPv4 packets
prop_ipv4_version_test() ->
    ?assert(proper:quickcheck(prop_ipv4_version(), [{numtests, 200}, noshrink])).

prop_ipv4_version() ->
    ?FORALL(Pkt, valid_ipv4_packet(),
        {ok, 4} =:= erlvpn_packet:get_version(Pkt)).

%% Property: source and dest IPs extracted from valid packets are correct
prop_ipv4_src_dst_test() ->
    ?assert(proper:quickcheck(prop_ipv4_src_dst(), [{numtests, 200}, noshrink])).

prop_ipv4_src_dst() ->
    ?FORALL({SrcIP, DstIP, Pkt}, ipv4_with_known_ips(),
        begin
            {ok, SrcIP} =:= erlvpn_packet:get_src_ip(Pkt) andalso
            {ok, DstIP} =:= erlvpn_packet:get_dst_ip(Pkt)
        end).

%%====================================================================
%% Generators
%%====================================================================

ipv4_tuple() ->
    {octet(), octet(), octet(), octet()}.

octet() ->
    integer(0, 255).

ipv6_tuple() ->
    {word(), word(), word(), word(), word(), word(), word(), word()}.

word() ->
    integer(0, 65535).

valid_ipv4_packet() ->
    ?LET({SrcIP, DstIP, Payload}, {ipv4_tuple(), ipv4_tuple(), binary()},
        begin
            {SA, SB, SC, SD} = SrcIP,
            {DA, DB, DC, DD} = DstIP,
            PayloadLen = byte_size(Payload),
            TotalLen = 20 + PayloadLen,
            <<16#45, 0,
              TotalLen:16/big,
              0, 0, 0, 0,
              64, 6,
              0, 0,
              SA, SB, SC, SD,
              DA, DB, DC, DD,
              Payload/binary>>
        end).

ipv4_with_known_ips() ->
    ?LET({SrcIP, DstIP, Payload}, {ipv4_tuple(), ipv4_tuple(), binary()},
        begin
            {SA, SB, SC, SD} = SrcIP,
            {DA, DB, DC, DD} = DstIP,
            PayloadLen = byte_size(Payload),
            TotalLen = 20 + PayloadLen,
            Pkt = <<16#45, 0,
                    TotalLen:16/big,
                    0, 0, 0, 0,
                    64, 6,
                    0, 0,
                    SA, SB, SC, SD,
                    DA, DB, DC, DD,
                    Payload/binary>>,
            {SrcIP, DstIP, Pkt}
        end).
