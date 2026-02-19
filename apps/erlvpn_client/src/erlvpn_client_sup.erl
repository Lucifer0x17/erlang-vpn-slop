%%%-------------------------------------------------------------------
%%% @doc ErlVPN Client Root Supervisor
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_client_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 5,
        period => 60
    },
    Children = [
        #{id => erlvpn_client_conn,
          start => {erlvpn_client_conn, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [erlvpn_client_conn]},

        #{id => erlvpn_client_tun,
          start => {erlvpn_client_tun, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [erlvpn_client_tun]},

        #{id => erlvpn_client_dns,
          start => {erlvpn_client_dns, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [erlvpn_client_dns]},

        #{id => erlvpn_client_killswitch,
          start => {erlvpn_client_killswitch, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [erlvpn_client_killswitch]},

        #{id => erlvpn_client_forwarder,
          start => {erlvpn_client_forwarder, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [erlvpn_client_forwarder]}
    ],
    {ok, {SupFlags, Children}}.
