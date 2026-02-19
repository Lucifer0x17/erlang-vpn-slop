%%%-------------------------------------------------------------------
%%% @doc ErlVPN Cryptographic Utilities
%%%
%%% Session token generation/validation, hashing, and random
%%% number generation. Uses OTP crypto module exclusively.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_crypto).

-export([init_secret/0, get_secret/0,
         generate_session_token/3, validate_session_token/1,
         hash_token/1, verify_token_hash/2,
         random_bytes/1, random_hex/1, generate_session_id/0,
         constant_time_compare/2]).

-define(HMAC_ALGO, sha256).
-define(TOKEN_VERSION, 1).

%%====================================================================
%% Secret Key Management
%%====================================================================

%% @doc Initialize the server's HMAC secret key.
%% Generates a random 32-byte key and stores it in persistent_term.
-spec init_secret() -> ok.
init_secret() ->
    case persistent_term:get(erlvpn_hmac_secret, undefined) of
        undefined ->
            Secret = crypto:strong_rand_bytes(32),
            persistent_term:put(erlvpn_hmac_secret, Secret),
            ok;
        _Existing ->
            ok
    end.

%% @doc Retrieve the current HMAC secret.
-spec get_secret() -> binary().
get_secret() ->
    case persistent_term:get(erlvpn_hmac_secret, undefined) of
        undefined ->
            init_secret(),
            persistent_term:get(erlvpn_hmac_secret);
        Secret ->
            Secret
    end.

%%====================================================================
%% Session Token Generation/Validation
%%====================================================================

%% @doc Generate a signed session token.
%% Token format: base64(<<Version, Nonce, Expiry, ClientIdLen, ClientId,
%%                        IPBin, HMAC-SHA256>>)
-spec generate_session_token(binary(), inet:ip4_address(), pos_integer()) ->
    binary().
generate_session_token(ClientId, TunnelIP, TTLSeconds) when
      is_binary(ClientId), is_tuple(TunnelIP), is_integer(TTLSeconds) ->
    Secret = get_secret(),
    Nonce = crypto:strong_rand_bytes(16),
    Expiry = erlang:system_time(second) + TTLSeconds,
    IPBin = erlvpn_packet:ip_to_binary(TunnelIP),
    ClientIdLen = byte_size(ClientId),
    Data = <<?TOKEN_VERSION:8, Nonce/binary, Expiry:64/big,
             ClientIdLen:16/big, ClientId/binary, IPBin/binary>>,
    Mac = crypto:mac(hmac, ?HMAC_ALGO, Secret, Data),
    base64:encode(<<Data/binary, Mac/binary>>).

%% @doc Validate a session token. Checks HMAC and expiry.
-spec validate_session_token(binary()) ->
    {ok, #{client_id := binary(), tunnel_ip := tuple(), expiry := integer()}}
    | {error, term()}.
validate_session_token(Token) when is_binary(Token) ->
    try
        Decoded = base64:decode(Token),
        validate_decoded_token(Decoded)
    catch
        error:_ -> {error, invalid_encoding}
    end.

validate_decoded_token(<<?TOKEN_VERSION:8, Nonce:16/binary, Expiry:64/big,
                         ClientIdLen:16/big, ClientId:ClientIdLen/binary,
                         IPBin:4/binary, Mac:32/binary>>) ->
    Secret = get_secret(),
    Data = <<?TOKEN_VERSION:8, Nonce/binary, Expiry:64/big,
             ClientIdLen:16/big, ClientId/binary, IPBin/binary>>,
    ExpectedMac = crypto:mac(hmac, ?HMAC_ALGO, Secret, Data),
    case constant_time_compare(Mac, ExpectedMac) of
        true ->
            Now = erlang:system_time(second),
            case Expiry > Now of
                true ->
                    {ok, IPTuple} = erlvpn_packet:binary_to_ip(IPBin),
                    {ok, #{client_id => ClientId,
                           tunnel_ip => IPTuple,
                           expiry => Expiry}};
                false ->
                    {error, expired}
            end;
        false ->
            {error, invalid_signature}
    end;
validate_decoded_token(<<Version:8, _/binary>>) when Version =/= ?TOKEN_VERSION ->
    {error, {unsupported_version, Version}};
validate_decoded_token(_) ->
    {error, malformed_token}.

%%====================================================================
%% Token Hashing (for storage)
%%====================================================================

%% @doc Hash a token with SHA256 for storage.
-spec hash_token(binary() | string()) -> binary().
hash_token(Token) when is_list(Token) ->
    hash_token(list_to_binary(Token));
hash_token(Token) when is_binary(Token) ->
    crypto:hash(sha256, Token).

%% @doc Verify a token against a stored hash.
-spec verify_token_hash(binary() | string(), binary()) -> boolean().
verify_token_hash(Token, StoredHash) ->
    constant_time_compare(hash_token(Token), StoredHash).

%%====================================================================
%% Random Generation
%%====================================================================

%% @doc Generate N cryptographically secure random bytes.
-spec random_bytes(pos_integer()) -> binary().
random_bytes(N) when is_integer(N), N > 0 ->
    crypto:strong_rand_bytes(N).

%% @doc Generate N random bytes as a hex string.
-spec random_hex(pos_integer()) -> binary().
random_hex(N) when is_integer(N), N > 0 ->
    Bytes = crypto:strong_rand_bytes(N),
    binary:encode_hex(Bytes, lowercase).

%% @doc Generate a unique 16-byte session ID as hex.
-spec generate_session_id() -> binary().
generate_session_id() ->
    random_hex(16).

%%====================================================================
%% Constant-Time Comparison
%%====================================================================

%% @doc Compare two binaries in constant time to prevent timing attacks.
-spec constant_time_compare(binary(), binary()) -> boolean().
constant_time_compare(A, B) when byte_size(A) =/= byte_size(B) ->
    false;
constant_time_compare(A, B) ->
    constant_time_compare(A, B, 0).

constant_time_compare(<<>>, <<>>, Acc) ->
    Acc =:= 0;
constant_time_compare(<<X:8, RestA/binary>>, <<Y:8, RestB/binary>>, Acc) ->
    constant_time_compare(RestA, RestB, Acc bor (X bxor Y)).
