-module(erlvpn_router_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlvpn_common/include/erlvpn.hrl").

%%====================================================================
%% Test fixtures
%%====================================================================

router_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
         fun register_and_lookup/1,
         fun lookup_not_found/1,
         fun unregister_route/1,
         fun replace_route/1,
         fun lookup_by_pid/1,
         fun route_count/1,
         fun get_all_routes/1,
         fun auto_cleanup_on_process_death/1
     ]}.

setup() ->
    {ok, Pid} = erlvpn_router:start_link(),
    Pid.

cleanup(Pid) ->
    gen_server:stop(Pid).

%%====================================================================
%% Tests
%%====================================================================

register_and_lookup(_Pid) ->
    fun() ->
        IP = {10, 8, 0, 5},
        StreamRef = make_ref(),
        ok = erlvpn_router:register_route(IP, self(), StreamRef),
        ?assertEqual({ok, self(), StreamRef}, erlvpn_router:lookup(IP))
    end.

lookup_not_found(_Pid) ->
    fun() ->
        ?assertEqual(not_found, erlvpn_router:lookup({10, 8, 0, 99}))
    end.

unregister_route(_Pid) ->
    fun() ->
        IP = {10, 8, 0, 10},
        ok = erlvpn_router:register_route(IP, self(), make_ref()),
        ?assertMatch({ok, _, _}, erlvpn_router:lookup(IP)),
        ok = erlvpn_router:unregister_route(IP),
        ?assertEqual(not_found, erlvpn_router:lookup(IP))
    end.

replace_route(_Pid) ->
    fun() ->
        IP = {10, 8, 0, 20},
        Ref1 = make_ref(),
        Ref2 = make_ref(),
        Pid1 = spawn(fun() -> receive stop -> ok end end),
        ok = erlvpn_router:register_route(IP, Pid1, Ref1),
        %% Replace with new pid/stream
        ok = erlvpn_router:register_route(IP, self(), Ref2),
        ?assertEqual({ok, self(), Ref2}, erlvpn_router:lookup(IP)),
        Pid1 ! stop
    end.

lookup_by_pid(_Pid) ->
    fun() ->
        IP = {10, 8, 0, 30},
        ok = erlvpn_router:register_route(IP, self(), make_ref()),
        ?assertEqual({ok, IP}, erlvpn_router:lookup_pid(self())),
        ?assertEqual(not_found, erlvpn_router:lookup_pid(list_to_pid("<0.9999.0>")))
    end.

route_count(_Pid) ->
    fun() ->
        ?assertEqual(0, erlvpn_router:route_count()),
        ok = erlvpn_router:register_route({10, 8, 0, 40}, self(), make_ref()),
        ?assertEqual(1, erlvpn_router:route_count()),
        P2 = spawn(fun() -> receive stop -> ok end end),
        ok = erlvpn_router:register_route({10, 8, 0, 41}, P2, make_ref()),
        ?assertEqual(2, erlvpn_router:route_count()),
        P2 ! stop
    end.

get_all_routes(_Pid) ->
    fun() ->
        ?assertEqual([], erlvpn_router:get_all_routes()),
        ok = erlvpn_router:register_route({10, 8, 0, 50}, self(), make_ref()),
        Routes = erlvpn_router:get_all_routes(),
        ?assertEqual(1, length(Routes))
    end.

auto_cleanup_on_process_death(_Pid) ->
    fun() ->
        IP = {10, 8, 0, 60},
        ChildPid = spawn(fun() -> receive stop -> ok end end),
        ok = erlvpn_router:register_route(IP, ChildPid, make_ref()),
        ?assertMatch({ok, _, _}, erlvpn_router:lookup(IP)),
        %% Kill the process
        ChildPid ! stop,
        %% Give the monitor time to fire
        timer:sleep(100),
        ?assertEqual(not_found, erlvpn_router:lookup(IP))
    end.
