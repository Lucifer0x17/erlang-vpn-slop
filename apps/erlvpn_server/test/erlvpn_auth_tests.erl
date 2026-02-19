-module(erlvpn_auth_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlvpn_common/include/erlvpn.hrl").

%%====================================================================
%% Test fixtures
%%====================================================================

auth_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
         fun add_and_authenticate_token/1,
         fun authenticate_invalid_token/1,
         fun remove_token/1,
         fun list_clients/1,
         fun rate_limiting/1,
         fun unsupported_method/1
     ]}.

setup() ->
    erlvpn_crypto:init_secret(),
    {ok, Pid} = erlvpn_auth:start_link([{auth_method, token}]),
    Pid.

cleanup(Pid) ->
    gen_server:stop(Pid).

%%====================================================================
%% Tests
%%====================================================================

add_and_authenticate_token(_Pid) ->
    fun() ->
        ok = erlvpn_auth:add_token(<<"secret_token_123">>, <<"user1">>),
        ?assertEqual({ok, <<"user1">>},
                     erlvpn_auth:authenticate(token, <<"secret_token_123">>))
    end.

authenticate_invalid_token(_Pid) ->
    fun() ->
        ?assertEqual({error, invalid_token},
                     erlvpn_auth:authenticate(token, <<"wrong_token">>))
    end.

remove_token(_Pid) ->
    fun() ->
        ok = erlvpn_auth:add_token(<<"temp_token">>, <<"temp_user">>),
        ?assertEqual({ok, <<"temp_user">>},
                     erlvpn_auth:authenticate(token, <<"temp_token">>)),
        ok = erlvpn_auth:remove_token(<<"temp_token">>),
        ?assertEqual({error, invalid_token},
                     erlvpn_auth:authenticate(token, <<"temp_token">>))
    end.

list_clients(_Pid) ->
    fun() ->
        ok = erlvpn_auth:add_token(<<"tok1">>, <<"client_a">>),
        ok = erlvpn_auth:add_token(<<"tok2">>, <<"client_b">>),
        Clients = erlvpn_auth:list_clients(),
        ?assert(lists:member(<<"client_a">>, Clients)),
        ?assert(lists:member(<<"client_b">>, Clients))
    end.

rate_limiting(_Pid) ->
    fun() ->
        ClientIP = {192, 168, 1, 100},
        %% First check should pass
        ?assertEqual(ok, erlvpn_auth:check_rate_limit(ClientIP)),
        %% Simulate 5 failures
        lists:foreach(fun(_) ->
            erlvpn_auth:authenticate(token, <<"bad">>, ClientIP)
        end, lists:seq(1, 5)),
        %% Should now be rate limited
        ?assertEqual({error, rate_limited},
                     erlvpn_auth:check_rate_limit(ClientIP))
    end.

unsupported_method(_Pid) ->
    fun() ->
        ?assertMatch({error, _},
                     erlvpn_auth:authenticate(certificate, <<"cert_data">>))
    end.

%%====================================================================
%% Token file loading test
%%====================================================================

load_tokens_from_file_test() ->
    erlvpn_crypto:init_secret(),
    %% Create a temp token file
    TmpFile = "/tmp/erlvpn_test_tokens_" ++ integer_to_list(erlang:unique_integer([positive])),
    ok = file:write_file(TmpFile, <<"token_abc user_alice\ntoken_def user_bob\n">>),
    {ok, Pid} = erlvpn_auth:start_link([{token_file, TmpFile}]),
    ?assertEqual({ok, <<"user_alice">>},
                 erlvpn_auth:authenticate(token, <<"token_abc">>)),
    ?assertEqual({ok, <<"user_bob">>},
                 erlvpn_auth:authenticate(token, <<"token_def">>)),
    gen_server:stop(Pid),
    file:delete(TmpFile).

load_tokens_missing_file_test() ->
    erlvpn_crypto:init_secret(),
    {ok, Pid} = erlvpn_auth:start_link([{token_file, "/nonexistent/path"}]),
    %% Should start successfully even if file doesn't exist
    ?assert(is_process_alive(Pid)),
    gen_server:stop(Pid).
