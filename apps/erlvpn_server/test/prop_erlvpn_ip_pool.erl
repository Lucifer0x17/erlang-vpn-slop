-module(prop_erlvpn_ip_pool).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Properties
%%====================================================================

%% Property: all allocated IPs are unique
prop_unique_allocations_test() ->
    ?assert(proper:quickcheck(prop_unique_allocations(), [{numtests, 50}, noshrink])).

prop_unique_allocations() ->
    ?FORALL(N, integer(1, 50),
        begin
            {ok, Pid} = erlvpn_ip_pool:start_link("10.0.0.0/24"),
            IPs = allocate_n(N),
            %% All IPs should be unique
            UniqueIPs = lists:usort(IPs),
            Result = length(IPs) =:= length(UniqueIPs),
            gen_server:stop(Pid),
            Result
        end).

%% Property: released IPs can be reallocated
prop_release_reallocate_test() ->
    ?assert(proper:quickcheck(prop_release_reallocate(), [{numtests, 50}, noshrink])).

prop_release_reallocate() ->
    ?FORALL(N, integer(1, 20),
        begin
            {ok, Pid} = erlvpn_ip_pool:start_link("10.0.0.0/24"),
            IPs = allocate_n(N),
            AvailBefore = erlvpn_ip_pool:available_count(),
            %% Release all
            lists:foreach(fun(IP) -> erlvpn_ip_pool:release(IP) end, IPs),
            AvailAfter = erlvpn_ip_pool:available_count(),
            %% Available count should increase by N
            Result = AvailAfter =:= AvailBefore + N,
            gen_server:stop(Pid),
            Result
        end).

%% Property: allocated count + available count = total
prop_counts_consistent_test() ->
    ?assert(proper:quickcheck(prop_counts_consistent(), [{numtests, 50}, noshrink])).

prop_counts_consistent() ->
    ?FORALL(N, integer(1, 30),
        begin
            {ok, Pid} = erlvpn_ip_pool:start_link("10.0.0.0/24"),
            Total = erlvpn_ip_pool:available_count(),
            _IPs = allocate_n(N),
            Alloc = erlvpn_ip_pool:allocated_count(),
            Avail = erlvpn_ip_pool:available_count(),
            Result = Alloc + Avail =:= Total,
            gen_server:stop(Pid),
            Result
        end).

%%====================================================================
%% Helpers
%%====================================================================

allocate_n(N) ->
    allocate_n(N, []).

allocate_n(0, Acc) ->
    lists:reverse(Acc);
allocate_n(N, Acc) ->
    case erlvpn_ip_pool:allocate() of
        {ok, IP} -> allocate_n(N - 1, [IP | Acc]);
        {error, exhausted} -> lists:reverse(Acc)
    end.
