%%%-------------------------------------------------------------------
%%% @doc ErlVPN Routing Table Manager
%%%
%%% Manages the ETS-based routing table that maps tunnel IPs to
%%% client session pids and QUIC streams. Uses ordered_set with
%%% read_concurrency for fast lookups on the packet forwarding path.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_router).

-behaviour(gen_server).

-include_lib("erlvpn_common/include/erlvpn.hrl").
-include_lib("kernel/include/logger.hrl").

%% API
-export([start_link/0, register_route/3, unregister_route/1,
         lookup/1, lookup_pid/1, get_all_routes/0, route_count/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    monitors = #{} :: #{reference() => inet:ip4_address()}
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Register a route for a tunnel IP.
-spec register_route(inet:ip4_address(), pid(), reference() | undefined) -> ok.
register_route(TunnelIP, ClientPid, QUICStream) ->
    gen_server:call(?MODULE, {register, TunnelIP, ClientPid, QUICStream}).

%% @doc Remove a route for a tunnel IP.
-spec unregister_route(inet:ip4_address()) -> ok.
unregister_route(TunnelIP) ->
    gen_server:call(?MODULE, {unregister, TunnelIP}).

%% @doc Look up a route by tunnel IP. Called on the hot path,
%% reads directly from ETS for performance (no gen_server call).
-spec lookup(inet:ip4_address()) -> {ok, pid(), reference() | undefined} | not_found.
lookup(TunnelIP) ->
    case ets:lookup(?ROUTE_TABLE, TunnelIP) of
        [{_, Pid, Stream, _Meta}] -> {ok, Pid, Stream};
        [] -> not_found
    end.

%% @doc Find route by client pid (reverse lookup, slower).
-spec lookup_pid(pid()) -> {ok, inet:ip4_address()} | not_found.
lookup_pid(ClientPid) ->
    case ets:match(?ROUTE_TABLE, {'$1', ClientPid, '_', '_'}) of
        [[IP] | _] -> {ok, IP};
        [] -> not_found
    end.

%% @doc Get all routes.
-spec get_all_routes() -> [{inet:ip4_address(), pid(), reference() | undefined, map()}].
get_all_routes() ->
    ets:tab2list(?ROUTE_TABLE).

%% @doc Get number of active routes.
-spec route_count() -> non_neg_integer().
route_count() ->
    ets:info(?ROUTE_TABLE, size).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    ets:new(?ROUTE_TABLE, [named_table, ordered_set, public,
                           {read_concurrency, true},
                           {write_concurrency, false}]),
    ?LOG_INFO(#{msg => "Router started", table => ?ROUTE_TABLE}),
    {ok, #state{}}.

handle_call({register, TunnelIP, ClientPid, QUICStream}, _From,
            #state{monitors = Mons} = State) ->
    %% Remove old route for this IP if it exists
    case ets:lookup(?ROUTE_TABLE, TunnelIP) of
        [{_, OldPid, _, _}] when OldPid =/= ClientPid ->
            ?LOG_INFO(#{msg => "Replacing existing route",
                        ip => erlvpn_packet:ip_to_string(TunnelIP),
                        old_pid => OldPid, new_pid => ClientPid}),
            %% Demonitor old pid if no other routes reference it
            Mons1 = maybe_demonitor(OldPid, TunnelIP, Mons);
        _ ->
            Mons1 = Mons
    end,
    %% Insert new route
    Meta = #{registered_at => erlang:monotonic_time()},
    ets:insert(?ROUTE_TABLE, {TunnelIP, ClientPid, QUICStream, Meta}),
    %% Monitor the client pid
    MonRef = monitor(process, ClientPid),
    Mons2 = maps:put(MonRef, TunnelIP, Mons1),
    ?LOG_INFO(#{msg => "Route registered",
                ip => erlvpn_packet:ip_to_string(TunnelIP),
                pid => ClientPid}),
    {reply, ok, State#state{monitors = Mons2}};

handle_call({unregister, TunnelIP}, _From, #state{monitors = Mons} = State) ->
    case ets:lookup(?ROUTE_TABLE, TunnelIP) of
        [{_, ClientPid, _, _}] ->
            ets:delete(?ROUTE_TABLE, TunnelIP),
            Mons1 = maybe_demonitor(ClientPid, TunnelIP, Mons),
            ?LOG_INFO(#{msg => "Route unregistered",
                        ip => erlvpn_packet:ip_to_string(TunnelIP)}),
            {reply, ok, State#state{monitors = Mons1}};
        [] ->
            {reply, ok, State}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', MonRef, process, Pid, Reason}, #state{monitors = Mons} = State) ->
    case maps:take(MonRef, Mons) of
        {TunnelIP, Mons1} ->
            ets:delete(?ROUTE_TABLE, TunnelIP),
            ?LOG_INFO(#{msg => "Route removed (process down)",
                        ip => erlvpn_packet:ip_to_string(TunnelIP),
                        pid => Pid, reason => Reason}),
            {noreply, State#state{monitors = Mons1}};
        error ->
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ?LOG_INFO(#{msg => "Router terminating"}),
    ok.

%%====================================================================
%% Internal
%%====================================================================

maybe_demonitor(Pid, _TunnelIP, Mons) ->
    %% Find and remove monitors for this pid
    maps:filter(
        fun(MonRef, _IP) ->
            case is_monitor_for_pid(MonRef, Pid) of
                true ->
                    demonitor(MonRef, [flush]),
                    false;
                false ->
                    true
            end
        end, Mons).

is_monitor_for_pid(MonRef, Pid) ->
    case erlang:process_info(Pid, monitored_by) of
        {monitored_by, MonList} ->
            lists:member(self(), MonList);
        undefined ->
            %% Process already dead, just clean up
            demonitor(MonRef, [flush]),
            true
    end.
