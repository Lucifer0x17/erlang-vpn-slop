-module(integ_auth_session_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlvpn_common/include/erlvpn.hrl").

%%====================================================================
%% Test fixture
%%====================================================================

auth_session_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
         fun max_auth_attempts_exceeded/1,
         fun token_added_after_session_start/1,
         fun token_removed_blocks_new_auth/1,
         fun session_resume_with_valid_token/1
     ]}.

setup() ->
    Pids = integ_test_helpers:start_server_deps(),
    ok = erlvpn_auth:add_token(<<"test_token">>, <<"client1">>),
    Pids.

cleanup(Pids) ->
    integ_test_helpers:stop_server_deps(Pids).

%%====================================================================
%% Tests
%%====================================================================

max_auth_attempts_exceeded(_Pids) ->
    fun() ->
        {ok, Pid} = integ_test_helpers:start_session(),
        Ref = monitor(process, Pid),
        %% Send 5 bad auth attempts (increments auth_attempts from 0 to 5)
        lists:foreach(fun(_) ->
            AuthFrame = erlvpn_protocol:encode_auth_request(token, <<"wrong">>),
            Pid ! {quic_data, self(), AuthFrame},
            timer:sleep(30)
        end, lists:seq(1, 5)),
        %% 6th attempt should trigger max exceeded -> disconnecting
        AuthFrame6 = erlvpn_protocol:encode_auth_request(token, <<"wrong">>),
        Pid ! {quic_data, self(), AuthFrame6},
        %% Session should terminate
        receive
            {'DOWN', Ref, process, Pid, _} -> ok
        after 5000 ->
            ?assert(false)
        end,
        %% Collect all frames - should include ERR_AUTH_FAILED
        Frames = integ_test_helpers:collect_sent_frames(100),
        Decoded = integ_test_helpers:decode_control_frames(Frames),
        ?assert(lists:any(fun({?MSG_ERROR, _}) -> true;
                             (_) -> false end, Decoded))
    end.

token_added_after_session_start(_Pids) ->
    fun() ->
        {ok, Pid} = integ_test_helpers:start_session(),
        %% Add a new token while session is already in connecting
        ok = erlvpn_auth:add_token(<<"late_token">>, <<"client_late">>),
        %% Auth with the new token should succeed
        AuthFrame = erlvpn_protocol:encode_auth_request(token, <<"late_token">>),
        Pid ! {quic_data, self(), AuthFrame},
        timer:sleep(100),
        {active, _} = sys:get_state(Pid),
        %% Verify the right client_id was assigned
        Info = erlvpn_session:get_info(Pid),
        ?assertEqual(<<"client_late">>, maps:get(client_id, Info)),
        erlvpn_session:disconnect(Pid),
        integ_test_helpers:wait_for_process_death(Pid, 2000)
    end.

token_removed_blocks_new_auth(_Pids) ->
    fun() ->
        %% Start and authenticate session 1
        {Pid1, _IP1, _} = integ_test_helpers:auth_session_to_active(),
        integ_test_helpers:flush_mailbox(),
        %% Remove the token
        ok = erlvpn_auth:remove_token(<<"test_token">>),
        %% Session 1 should still be active (already authenticated)
        {active, _} = sys:get_state(Pid1),
        %% New session with same token should fail
        {ok, Pid2} = integ_test_helpers:start_session(),
        AuthFrame = erlvpn_protocol:encode_auth_request(token, <<"test_token">>),
        Pid2 ! {quic_data, self(), AuthFrame},
        timer:sleep(100),
        %% Session 2 should still be in authenticating (auth failed)
        {authenticating, _} = sys:get_state(Pid2),
        %% Cleanup
        erlvpn_session:disconnect(Pid1),
        erlvpn_session:disconnect(Pid2),
        integ_test_helpers:wait_for_process_death(Pid1, 2000),
        integ_test_helpers:wait_for_process_death(Pid2, 2000)
    end.

session_resume_with_valid_token(_Pids) ->
    fun() ->
        %% Authenticate and get a session token
        {Pid1, TunnelIP, SessionToken} = integ_test_helpers:auth_session_to_active(),
        integ_test_helpers:flush_mailbox(),
        %% Disconnect session 1
        erlvpn_session:disconnect(Pid1),
        integ_test_helpers:wait_for_process_death(Pid1, 2000),
        timer:sleep(50),
        %% IP should be released
        ?assertNot(erlvpn_ip_pool:is_allocated(TunnelIP)),
        %% Start new session and resume with token
        {ok, Pid2} = integ_test_helpers:start_session(),
        ResumeFrame = erlvpn_protocol:encode_session_resume(SessionToken),
        Pid2 ! {quic_data, self(), ResumeFrame},
        timer:sleep(100),
        %% Session 2 should be active
        {active, _} = sys:get_state(Pid2),
        %% Should have the same tunnel IP (preferred allocation)
        Info = erlvpn_session:get_info(Pid2),
        ?assertEqual(TunnelIP, maps:get(tunnel_ip, Info)),
        erlvpn_session:disconnect(Pid2),
        integ_test_helpers:wait_for_process_death(Pid2, 2000)
    end.
