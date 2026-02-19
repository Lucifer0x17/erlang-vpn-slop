-module(erlvpn_protocol_tests).

-include_lib("eunit/include/eunit.hrl").
-include("erlvpn.hrl").

%%====================================================================
%% Control Frame Tests
%%====================================================================

encode_decode_control_roundtrip_test() ->
    Payload = {token, <<"my_secret_token">>},
    Encoded = erlvpn_protocol:encode_control(?MSG_AUTH_REQUEST, Payload),
    {ok, ?MSG_AUTH_REQUEST, Decoded, <<>>} = erlvpn_protocol:decode_control(Encoded),
    ?assertEqual(Payload, Decoded).

encode_decode_all_message_types_test_() ->
    Types = [
        {?MSG_AUTH_REQUEST,     {token, <<"tok">>}},
        {?MSG_AUTH_RESPONSE,    {ok, <<"session_token">>}},
        {?MSG_CONFIG_PUSH,      #{tunnel_ip => {10,8,0,5}, mtu => 1280}},
        {?MSG_KEEPALIVE,        {1234567890}},
        {?MSG_KEEPALIVE_ACK,    {1234567890}},
        {?MSG_DISCONNECT,       {normal}},
        {?MSG_BANDWIDTH_REPORT, {1000, 2000, 100, 200}},
        {?MSG_ROUTE_UPDATE,     {["10.0.0.0/8"], ["192.168.0.0/16"]}},
        {?MSG_DNS_CONFIG,       {["1.1.1.1"], ["example.com"]}},
        {?MSG_KILL_SWITCH,      {activate}},
        {?MSG_SESSION_RESUME,   {<<"token123">>}},
        {?MSG_ERROR,            {1, <<"auth failed">>}}
    ],
    [fun() ->
        Encoded = erlvpn_protocol:encode_control(Type, Payload),
        {ok, Type, Decoded, <<>>} = erlvpn_protocol:decode_control(Encoded),
        ?assertEqual(Payload, Decoded)
     end || {Type, Payload} <- Types].

decode_control_incomplete_data_test() ->
    Encoded = erlvpn_protocol:encode_control(?MSG_KEEPALIVE, {12345}),
    %% Truncate the data
    Partial = binary:part(Encoded, 0, byte_size(Encoded) - 2),
    ?assertMatch({more, _}, erlvpn_protocol:decode_control(Partial)).

decode_control_too_short_test() ->
    ?assertMatch({more, _}, erlvpn_protocol:decode_control(<<1, 0>>)),
    ?assertMatch({more, _}, erlvpn_protocol:decode_control(<<>>)),
    ?assertMatch({more, _}, erlvpn_protocol:decode_control(<<1>>)).

decode_control_multiple_frames_test() ->
    Frame1 = erlvpn_protocol:encode_control(?MSG_KEEPALIVE, {111}),
    Frame2 = erlvpn_protocol:encode_control(?MSG_KEEPALIVE, {222}),
    Combined = <<Frame1/binary, Frame2/binary>>,
    {ok, ?MSG_KEEPALIVE, {111}, Rest} = erlvpn_protocol:decode_control(Combined),
    {ok, ?MSG_KEEPALIVE, {222}, <<>>} = erlvpn_protocol:decode_control(Rest).

%%====================================================================
%% Data Frame Tests
%%====================================================================

encode_decode_data_roundtrip_test() ->
    %% Minimal IPv4 packet (20 bytes header)
    Packet = <<16#45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0,
               10, 8, 0, 5, 10, 8, 0, 1>>,
    Encoded = erlvpn_protocol:encode_data(Packet),
    {ok, Decoded, <<>>} = erlvpn_protocol:decode_data(Encoded),
    ?assertEqual(Packet, Decoded).

decode_data_incomplete_test() ->
    Packet = <<1, 2, 3, 4, 5>>,
    Encoded = erlvpn_protocol:encode_data(Packet),
    Partial = binary:part(Encoded, 0, byte_size(Encoded) - 2),
    ?assertMatch({more, _}, erlvpn_protocol:decode_data(Partial)).

decode_data_too_short_test() ->
    ?assertMatch({more, _}, erlvpn_protocol:decode_data(<<>>)),
    ?assertMatch({more, _}, erlvpn_protocol:decode_data(<<0>>)).

decode_data_multiple_frames_test() ->
    P1 = <<"packet1">>,
    P2 = <<"packet2">>,
    E1 = erlvpn_protocol:encode_data(P1),
    E2 = erlvpn_protocol:encode_data(P2),
    Combined = <<E1/binary, E2/binary>>,
    {ok, P1, Rest} = erlvpn_protocol:decode_data(Combined),
    {ok, P2, <<>>} = erlvpn_protocol:decode_data(Rest).

%%====================================================================
%% Convenience Encoder Tests
%%====================================================================

encode_auth_request_test() ->
    Bin = erlvpn_protocol:encode_auth_request(token, <<"mytoken">>),
    {ok, ?MSG_AUTH_REQUEST, {token, <<"mytoken">>}, <<>>} =
        erlvpn_protocol:decode_control(Bin).

encode_auth_response_test() ->
    Bin = erlvpn_protocol:encode_auth_response(ok, <<"session_tok">>),
    {ok, ?MSG_AUTH_RESPONSE, {ok, <<"session_tok">>}, <<>>} =
        erlvpn_protocol:decode_control(Bin).

encode_keepalive_test() ->
    Bin = erlvpn_protocol:encode_keepalive(),
    {ok, ?MSG_KEEPALIVE, {Ts}, <<>>} = erlvpn_protocol:decode_control(Bin),
    ?assert(is_integer(Ts)),
    ?assert(Ts > 0).

encode_disconnect_test() ->
    Bin = erlvpn_protocol:encode_disconnect(normal),
    {ok, ?MSG_DISCONNECT, {normal}, <<>>} = erlvpn_protocol:decode_control(Bin).

encode_error_test() ->
    Bin = erlvpn_protocol:encode_error(?ERR_AUTH_FAILED, <<"bad token">>),
    {ok, ?MSG_ERROR, {?ERR_AUTH_FAILED, <<"bad token">>}, <<>>} =
        erlvpn_protocol:decode_control(Bin).

encode_kill_switch_test() ->
    Bin = erlvpn_protocol:encode_kill_switch(activate),
    {ok, ?MSG_KILL_SWITCH, {activate}, <<>>} = erlvpn_protocol:decode_control(Bin).

encode_session_resume_test() ->
    Bin = erlvpn_protocol:encode_session_resume(<<"tok123">>),
    {ok, ?MSG_SESSION_RESUME, {<<"tok123">>}, <<>>} =
        erlvpn_protocol:decode_control(Bin).

encode_bandwidth_report_test() ->
    Bin = erlvpn_protocol:encode_bandwidth_report(100, 200, 10, 20),
    {ok, ?MSG_BANDWIDTH_REPORT, {100, 200, 10, 20}, <<>>} =
        erlvpn_protocol:decode_control(Bin).

encode_config_push_test() ->
    Config = #{tunnel_ip => {10,8,0,5}, mtu => 1280},
    Bin = erlvpn_protocol:encode_config_push(Config),
    {ok, ?MSG_CONFIG_PUSH, Config, <<>>} = erlvpn_protocol:decode_control(Bin).

%%====================================================================
%% decode_message Tests
%%====================================================================

decode_message_auth_request_test() ->
    {ok, auth_request, #{method := token, credentials := <<"tok">>}} =
        erlvpn_protocol:decode_message(?MSG_AUTH_REQUEST, {token, <<"tok">>}).

decode_message_unknown_type_test() ->
    ?assertMatch({error, {unknown_message_type, 99}},
                 erlvpn_protocol:decode_message(99, {anything})).
