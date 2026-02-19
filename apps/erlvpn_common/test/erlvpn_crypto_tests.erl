-module(erlvpn_crypto_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Setup/Teardown
%%====================================================================

setup() ->
    %% Ensure secret is initialized
    erlvpn_crypto:init_secret().

%%====================================================================
%% Session Token Tests
%%====================================================================

generate_and_validate_token_test() ->
    setup(),
    ClientId = <<"user123">>,
    IP = {10, 8, 0, 5},
    TTL = 3600,
    Token = erlvpn_crypto:generate_session_token(ClientId, IP, TTL),
    ?assert(is_binary(Token)),
    ?assert(byte_size(Token) > 0),
    {ok, Info} = erlvpn_crypto:validate_session_token(Token),
    ?assertEqual(ClientId, maps:get(client_id, Info)),
    ?assertEqual(IP, maps:get(tunnel_ip, Info)),
    ?assert(maps:get(expiry, Info) > erlang:system_time(second)).

validate_expired_token_test() ->
    setup(),
    %% Create a token with 0 TTL (already expired)
    Token = erlvpn_crypto:generate_session_token(<<"user">>, {10,8,0,5}, 0),
    %% Wait a second for it to expire
    timer:sleep(1100),
    ?assertEqual({error, expired}, erlvpn_crypto:validate_session_token(Token)).

validate_invalid_token_test() ->
    setup(),
    ?assertEqual({error, invalid_encoding},
                 erlvpn_crypto:validate_session_token(<<"not_base64!!!">>)).

validate_tampered_token_test() ->
    setup(),
    Token = erlvpn_crypto:generate_session_token(<<"user">>, {10,8,0,1}, 3600),
    Decoded = base64:decode(Token),
    %% Flip a byte in the middle
    Pos = byte_size(Decoded) div 2,
    <<Pre:Pos/binary, Byte:8, Post/binary>> = Decoded,
    Tampered = <<Pre/binary, (Byte bxor 16#FF):8, Post/binary>>,
    TamperedToken = base64:encode(Tampered),
    Result = erlvpn_crypto:validate_session_token(TamperedToken),
    ?assertMatch({error, _}, Result).

%%====================================================================
%% Token Hashing Tests
%%====================================================================

hash_token_test() ->
    Hash = erlvpn_crypto:hash_token(<<"mysecret">>),
    ?assertEqual(32, byte_size(Hash)),
    %% Same input produces same hash
    ?assertEqual(Hash, erlvpn_crypto:hash_token(<<"mysecret">>)).

hash_token_string_input_test() ->
    Hash1 = erlvpn_crypto:hash_token("mysecret"),
    Hash2 = erlvpn_crypto:hash_token(<<"mysecret">>),
    ?assertEqual(Hash1, Hash2).

verify_token_hash_test() ->
    Token = <<"my_auth_token">>,
    Hash = erlvpn_crypto:hash_token(Token),
    ?assert(erlvpn_crypto:verify_token_hash(Token, Hash)),
    ?assertNot(erlvpn_crypto:verify_token_hash(<<"wrong_token">>, Hash)).

%%====================================================================
%% Random Generation Tests
%%====================================================================

random_bytes_test() ->
    B1 = erlvpn_crypto:random_bytes(32),
    B2 = erlvpn_crypto:random_bytes(32),
    ?assertEqual(32, byte_size(B1)),
    ?assertEqual(32, byte_size(B2)),
    %% Two random generations should be different
    ?assertNotEqual(B1, B2).

random_hex_test() ->
    Hex = erlvpn_crypto:random_hex(16),
    ?assertEqual(32, byte_size(Hex)),  %% 16 bytes = 32 hex chars
    %% Should only contain hex characters
    ?assert(is_valid_hex(Hex)).

generate_session_id_test() ->
    Id1 = erlvpn_crypto:generate_session_id(),
    Id2 = erlvpn_crypto:generate_session_id(),
    ?assertEqual(32, byte_size(Id1)),  %% 16 bytes = 32 hex chars
    ?assertNotEqual(Id1, Id2).

%%====================================================================
%% Constant Time Compare Tests
%%====================================================================

constant_time_compare_equal_test() ->
    ?assert(erlvpn_crypto:constant_time_compare(<<"hello">>, <<"hello">>)).

constant_time_compare_different_test() ->
    ?assertNot(erlvpn_crypto:constant_time_compare(<<"hello">>, <<"world">>)).

constant_time_compare_different_length_test() ->
    ?assertNot(erlvpn_crypto:constant_time_compare(<<"hello">>, <<"hi">>)).

constant_time_compare_empty_test() ->
    ?assert(erlvpn_crypto:constant_time_compare(<<>>, <<>>)).

%%====================================================================
%% Secret Management Tests
%%====================================================================

init_secret_idempotent_test() ->
    erlvpn_crypto:init_secret(),
    Secret1 = erlvpn_crypto:get_secret(),
    erlvpn_crypto:init_secret(),
    Secret2 = erlvpn_crypto:get_secret(),
    ?assertEqual(Secret1, Secret2).

get_secret_auto_init_test() ->
    %% get_secret should auto-init if not already initialized
    Secret = erlvpn_crypto:get_secret(),
    ?assertEqual(32, byte_size(Secret)).

%%====================================================================
%% Helpers
%%====================================================================

is_valid_hex(<<>>) -> true;
is_valid_hex(<<C, Rest/binary>>) when
      (C >= $0 andalso C =< $9) orelse
      (C >= $a andalso C =< $f) orelse
      (C >= $A andalso C =< $F) ->
    is_valid_hex(Rest);
is_valid_hex(_) -> false.
