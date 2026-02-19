%%%-------------------------------------------------------------------
%%% @doc ErlVPN Wire Protocol - Encode/Decode
%%%
%%% Control Frame Format:
%%%   <<Type:8, Length:16/big, Payload/binary>>
%%%
%%% Data Frame Format (QUIC streams):
%%%   <<Length:16/big, IPPacket/binary>>
%%%
%%% Payloads are serialized using Erlang External Term Format
%%% (term_to_binary/binary_to_term) with safe decoding.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_protocol).

-include("erlvpn.hrl").

%% Control frame API
-export([encode_control/2, decode_control/1]).
%% Data frame API
-export([encode_data/1, decode_data/1]).
%% Convenience encoders
-export([encode_auth_request/2, encode_auth_response/2,
         encode_config_push/1, encode_keepalive/0,
         encode_keepalive_ack/1, encode_disconnect/1,
         encode_bandwidth_report/4, encode_route_update/2,
         encode_dns_config/2, encode_kill_switch/1,
         encode_session_resume/1, encode_error/2]).
%% Convenience decoders
-export([decode_message/2]).

%%====================================================================
%% Types
%%====================================================================

-type msg_type() :: 16#01..16#0B | 16#FF.
-type decode_result() :: {ok, msg_type(), term(), binary()}
                       | {more, binary()}
                       | {error, term()}.
-type data_result() :: {ok, binary(), binary()}
                     | {more, binary()}
                     | {error, term()}.

-export_type([msg_type/0, decode_result/0, data_result/0]).

%%====================================================================
%% Control Frame Encode/Decode
%%====================================================================

-spec encode_control(msg_type(), term()) -> binary().
encode_control(Type, Payload) when is_integer(Type), Type >= 0, Type =< 255 ->
    PayloadBin = term_to_binary(Payload),
    PayloadLen = byte_size(PayloadBin),
    case PayloadLen > ?CONTROL_FRAME_MAX_LEN of
        true ->
            error({payload_too_large, PayloadLen, ?CONTROL_FRAME_MAX_LEN});
        false ->
            <<Type:8, PayloadLen:16/big, PayloadBin/binary>>
    end.

-spec decode_control(binary()) -> decode_result().
decode_control(<<Type:8, Len:16/big, Rest/binary>>) when byte_size(Rest) >= Len ->
    <<PayloadBin:Len/binary, Remaining/binary>> = Rest,
    try binary_to_term(PayloadBin, [safe]) of
        Payload ->
            {ok, Type, Payload, Remaining}
    catch
        error:badarg ->
            {error, {invalid_payload, Type}};
        _:Reason ->
            {error, {decode_failed, Reason}}
    end;
decode_control(<<_Type:8, _Len:16/big, _Rest/binary>> = Bin) ->
    {more, Bin};
decode_control(Bin) when byte_size(Bin) < 3 ->
    {more, Bin};
decode_control(_) ->
    {error, invalid_frame}.

%%====================================================================
%% Data Frame Encode/Decode
%%====================================================================

-spec encode_data(binary()) -> binary().
encode_data(IPPacket) when is_binary(IPPacket) ->
    Len = byte_size(IPPacket),
    case Len > ?MAX_PACKET_SIZE of
        true -> error({packet_too_large, Len});
        false -> <<Len:16/big, IPPacket/binary>>
    end.

-spec decode_data(binary()) -> data_result().
decode_data(<<Len:16/big, Rest/binary>>) when byte_size(Rest) >= Len ->
    <<Packet:Len/binary, Remaining/binary>> = Rest,
    {ok, Packet, Remaining};
decode_data(<<_Len:16/big, _Rest/binary>> = Bin) ->
    {more, Bin};
decode_data(Bin) when byte_size(Bin) < 2 ->
    {more, Bin};
decode_data(_) ->
    {error, invalid_data_frame}.

%%====================================================================
%% Convenience Encoders
%%====================================================================

-spec encode_auth_request(atom(), term()) -> binary().
encode_auth_request(Method, Credentials) ->
    encode_control(?MSG_AUTH_REQUEST, {Method, Credentials}).

-spec encode_auth_response(ok | error, term()) -> binary().
encode_auth_response(Status, TokenOrReason) ->
    encode_control(?MSG_AUTH_RESPONSE, {Status, TokenOrReason}).

-spec encode_config_push(map()) -> binary().
encode_config_push(Config) when is_map(Config) ->
    encode_control(?MSG_CONFIG_PUSH, Config).

-spec encode_keepalive() -> binary().
encode_keepalive() ->
    encode_control(?MSG_KEEPALIVE, {erlang:system_time(millisecond)}).

-spec encode_keepalive_ack(integer()) -> binary().
encode_keepalive_ack(Timestamp) ->
    encode_control(?MSG_KEEPALIVE_ACK, {Timestamp}).

-spec encode_disconnect(atom()) -> binary().
encode_disconnect(Reason) ->
    encode_control(?MSG_DISCONNECT, {Reason}).

-spec encode_bandwidth_report(non_neg_integer(), non_neg_integer(),
                              non_neg_integer(), non_neg_integer()) -> binary().
encode_bandwidth_report(RxBytes, TxBytes, RxPackets, TxPackets) ->
    encode_control(?MSG_BANDWIDTH_REPORT,
                   {RxBytes, TxBytes, RxPackets, TxPackets}).

-spec encode_route_update([string()], [string()]) -> binary().
encode_route_update(AddRoutes, RemoveRoutes) ->
    encode_control(?MSG_ROUTE_UPDATE, {AddRoutes, RemoveRoutes}).

-spec encode_dns_config([string()], [string()]) -> binary().
encode_dns_config(DnsServers, SearchDomains) ->
    encode_control(?MSG_DNS_CONFIG, {DnsServers, SearchDomains}).

-spec encode_kill_switch(activate | release) -> binary().
encode_kill_switch(Action) when Action =:= activate; Action =:= release ->
    encode_control(?MSG_KILL_SWITCH, {Action}).

-spec encode_session_resume(binary()) -> binary().
encode_session_resume(SessionToken) when is_binary(SessionToken) ->
    encode_control(?MSG_SESSION_RESUME, {SessionToken}).

-spec encode_error(integer(), binary() | string()) -> binary().
encode_error(ErrorCode, Message) ->
    encode_control(?MSG_ERROR, {ErrorCode, iolist_to_binary([Message])}).

%%====================================================================
%% Convenience Decoder (dispatch by type)
%%====================================================================

-spec decode_message(msg_type(), term()) ->
    {ok, atom(), map()} | {error, term()}.
decode_message(?MSG_AUTH_REQUEST, {Method, Credentials}) ->
    {ok, auth_request, #{method => Method, credentials => Credentials}};

decode_message(?MSG_AUTH_RESPONSE, {Status, Value}) ->
    {ok, auth_response, #{status => Status, value => Value}};

decode_message(?MSG_CONFIG_PUSH, Config) when is_map(Config) ->
    {ok, config_push, Config};

decode_message(?MSG_KEEPALIVE, {Timestamp}) ->
    {ok, keepalive, #{timestamp => Timestamp}};

decode_message(?MSG_KEEPALIVE_ACK, {Timestamp}) ->
    {ok, keepalive_ack, #{timestamp => Timestamp}};

decode_message(?MSG_DISCONNECT, {Reason}) ->
    {ok, disconnect, #{reason => Reason}};

decode_message(?MSG_BANDWIDTH_REPORT, {Rx, Tx, RxP, TxP}) ->
    {ok, bandwidth_report, #{rx_bytes => Rx, tx_bytes => Tx,
                             rx_packets => RxP, tx_packets => TxP}};

decode_message(?MSG_ROUTE_UPDATE, {Add, Remove}) ->
    {ok, route_update, #{add => Add, remove => Remove}};

decode_message(?MSG_DNS_CONFIG, {Servers, Domains}) ->
    {ok, dns_config, #{servers => Servers, domains => Domains}};

decode_message(?MSG_KILL_SWITCH, {Action}) ->
    {ok, kill_switch, #{action => Action}};

decode_message(?MSG_SESSION_RESUME, {Token}) ->
    {ok, session_resume, #{token => Token}};

decode_message(?MSG_ERROR, {Code, Msg}) ->
    {ok, error, #{code => Code, message => Msg}};

decode_message(Type, _Payload) ->
    {error, {unknown_message_type, Type}}.
