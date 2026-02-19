%%%-------------------------------------------------------------------
%%% @doc ErlVPN Session Supervisor
%%%
%%% simple_one_for_one supervisor that manages per-client session
%%% processes. Each VPN client gets its own erlvpn_session child.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_session_sup).

-behaviour(supervisor).

-export([start_link/0, start_session/1, count_sessions/0]).
-export([init/1]).

%%====================================================================
%% API
%%====================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% @doc Start a new session for a client connection.
-spec start_session(map()) -> {ok, pid()} | {error, term()}.
start_session(Args) ->
    supervisor:start_child(?MODULE, [Args]).

%% @doc Count active sessions.
-spec count_sessions() -> non_neg_integer().
count_sessions() ->
    proplists:get_value(active, supervisor:count_children(?MODULE), 0).

%%====================================================================
%% Supervisor callback
%%====================================================================

init([]) ->
    SupFlags = #{
        strategy => simple_one_for_one,
        intensity => 10,
        period => 60
    },
    ChildSpec = #{
        id => erlvpn_session,
        start => {erlvpn_session, start_link, []},
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [erlvpn_session]
    },
    {ok, {SupFlags, [ChildSpec]}}.
