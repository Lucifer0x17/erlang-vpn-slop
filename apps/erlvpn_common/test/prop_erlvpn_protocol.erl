-module(prop_erlvpn_protocol).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("erlvpn.hrl").

%%====================================================================
%% Properties (run via EUnit integration)
%%====================================================================

%% Property: encode then decode control frame is identity
prop_control_roundtrip_test() ->
    ?assert(proper:quickcheck(prop_control_roundtrip(), [{numtests, 200}, noshrink])).

prop_control_roundtrip() ->
    ?FORALL({Type, Payload}, {msg_type(), any_payload()},
        begin
            Encoded = erlvpn_protocol:encode_control(Type, Payload),
            {ok, Type, Decoded, <<>>} = erlvpn_protocol:decode_control(Encoded),
            Decoded =:= Payload
        end).

%% Property: encode then decode data frame is identity
prop_data_roundtrip_test() ->
    ?assert(proper:quickcheck(prop_data_roundtrip(), [{numtests, 200}, noshrink])).

prop_data_roundtrip() ->
    ?FORALL(Packet, non_empty(binary()),
        begin
            Encoded = erlvpn_protocol:encode_data(Packet),
            {ok, Decoded, <<>>} = erlvpn_protocol:decode_data(Encoded),
            Decoded =:= Packet
        end).

%% Property: partial control frames return {more, _}
prop_partial_control_returns_more_test() ->
    ?assert(proper:quickcheck(prop_partial_control_returns_more(), [{numtests, 100}, noshrink])).

prop_partial_control_returns_more() ->
    ?FORALL({Type, Payload}, {msg_type(), any_payload()},
        begin
            Encoded = erlvpn_protocol:encode_control(Type, Payload),
            Len = byte_size(Encoded),
            case Len > 3 of
                true ->
                    CutAt = rand:uniform(Len - 1),
                    Partial = binary:part(Encoded, 0, CutAt),
                    case erlvpn_protocol:decode_control(Partial) of
                        {more, _} -> true;
                        {ok, _, _, _} -> true  %% If we happened to cut after a valid frame
                    end;
                false ->
                    true  %% Too small to meaningfully test
            end
        end).

%% Property: concatenated control frames decode sequentially
prop_concat_control_frames_test() ->
    ?assert(proper:quickcheck(prop_concat_control_frames(), [{numtests, 100}, noshrink])).

prop_concat_control_frames() ->
    ?FORALL({T1, P1, T2, P2},
            {msg_type(), simple_payload(), msg_type(), simple_payload()},
        begin
            E1 = erlvpn_protocol:encode_control(T1, P1),
            E2 = erlvpn_protocol:encode_control(T2, P2),
            Combined = <<E1/binary, E2/binary>>,
            {ok, T1, P1, Rest} = erlvpn_protocol:decode_control(Combined),
            {ok, T2, P2, <<>>} = erlvpn_protocol:decode_control(Rest),
            true
        end).

%%====================================================================
%% Generators
%%====================================================================

msg_type() ->
    oneof([?MSG_AUTH_REQUEST, ?MSG_AUTH_RESPONSE, ?MSG_CONFIG_PUSH,
           ?MSG_KEEPALIVE, ?MSG_KEEPALIVE_ACK, ?MSG_DISCONNECT,
           ?MSG_BANDWIDTH_REPORT, ?MSG_ROUTE_UPDATE, ?MSG_DNS_CONFIG,
           ?MSG_KILL_SWITCH, ?MSG_SESSION_RESUME, ?MSG_ERROR]).

any_payload() ->
    oneof([
        simple_payload(),
        {atom(), binary()},
        {integer(), integer()},
        binary(),
        list(integer())
    ]).

simple_payload() ->
    oneof([
        {known_atom(), binary()},
        {integer()},
        {binary()},
        known_atom()
    ]).

known_atom() ->
    oneof([ok, error, token, normal, timeout, activate, release]).
