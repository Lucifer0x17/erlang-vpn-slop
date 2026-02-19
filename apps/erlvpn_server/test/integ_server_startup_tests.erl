-module(integ_server_startup_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlvpn_common/include/erlvpn.hrl").

%%====================================================================
%% Test fixture
%%====================================================================

server_startup_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
         fun all_children_started/1,
         fun all_children_alive/1,
         fun named_processes_registered/1,
         fun ets_tables_exist/1,
         fun initial_route_count_zero/1
     ]}.

setup() ->
    erlvpn_crypto:init_secret(),
    %% Mock tuncer (not available on macOS)
    meck:new(tuncer, [non_strict]),
    meck:expect(tuncer, create, fun(_, _) -> {ok, self()} end),
    meck:expect(tuncer, devname, fun(_) -> <<"erlvpn0">> end),
    meck:expect(tuncer, up, fun(_, _) -> ok end),
    meck:expect(tuncer, destroy, fun(_) -> ok end),
    %% Mock quicer (NIF not available on macOS)
    meck:new(quicer, [non_strict]),
    meck:expect(quicer, listen, fun(_, _) -> {ok, make_ref()} end),
    meck:expect(quicer, close_listener, fun(_) -> ok end),
    %% Start the full supervision tree
    {ok, SupPid} = erlvpn_server_sup:start_link(),
    SupPid.

cleanup(SupPid) ->
    unlink(SupPid),
    exit(SupPid, shutdown),
    timer:sleep(200),
    meck:unload([tuncer, quicer]).

%%====================================================================
%% Tests
%%====================================================================

all_children_started(SupPid) ->
    fun() ->
        Children = supervisor:which_children(SupPid),
        ChildIds = [Id || {Id, _, _, _} <- Children],
        Expected = [erlvpn_metrics, erlvpn_router, erlvpn_ip_pool,
                    erlvpn_auth, erlvpn_dns, erlvpn_tun_manager,
                    erlvpn_session_sup, erlvpn_quic_listener],
        lists:foreach(fun(Id) ->
            ?assert(lists:member(Id, ChildIds))
        end, Expected),
        ?assertEqual(8, length(Children))
    end.

all_children_alive(SupPid) ->
    fun() ->
        Children = supervisor:which_children(SupPid),
        lists:foreach(fun({Id, Pid, _, _}) ->
            ?assert(is_pid(Pid)),
            ?assert(is_process_alive(Pid)),
            _ = Id
        end, Children)
    end.

named_processes_registered(_SupPid) ->
    fun() ->
        Names = [erlvpn_metrics, erlvpn_router, erlvpn_ip_pool,
                 erlvpn_auth, erlvpn_dns, erlvpn_tun_manager,
                 erlvpn_quic_listener],
        lists:foreach(fun(Name) ->
            Pid = whereis(Name),
            ?assertNotEqual(undefined, Pid)
        end, Names)
    end.

ets_tables_exist(_SupPid) ->
    fun() ->
        ?assertNotEqual(undefined, ets:info(?METRICS_TABLE, size)),
        ?assertNotEqual(undefined, ets:info(?ROUTE_TABLE, size))
    end.

initial_route_count_zero(_SupPid) ->
    fun() ->
        ?assertEqual(0, erlvpn_router:route_count()),
        ?assertEqual(0, erlvpn_ip_pool:allocated_count())
    end.
