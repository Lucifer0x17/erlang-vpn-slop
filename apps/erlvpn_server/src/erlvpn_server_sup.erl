%%%-------------------------------------------------------------------
%%% @doc ErlVPN Server Root Supervisor
%%%
%%% Starts all server components in the correct order:
%%% 1. Metrics (no deps)
%%% 2. Router (no deps)
%%% 3. IP Pool (depends on config)
%%% 4. Auth (depends on config, crypto)
%%% 5. DNS (depends on config)
%%% 6. TUN Manager (depends on router, config)
%%% 7. Session Supervisor (depends on pool, router, auth)
%%% 8. QUIC Listener (depends on session_sup)
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_server_sup).

-behaviour(supervisor).

-include_lib("erlvpn_common/include/erlvpn.hrl").
-include_lib("kernel/include/logger.hrl").

-export([start_link/0]).
-export([init/1]).

%%====================================================================
%% API
%%====================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%%====================================================================
%% Supervisor callback
%%====================================================================

init([]) ->
    %% Initialize crypto secret before anything else
    erlvpn_crypto:init_secret(),

    CIDR = erlvpn_config:get(tunnel_ipv4_cidr, ?DEFAULT_TUNNEL_CIDR),

    SupFlags = #{
        strategy => one_for_one,
        intensity => 10,
        period => 60
    },

    Children = [
        %% 1. Metrics collector
        #{id => erlvpn_metrics,
          start => {erlvpn_metrics, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [erlvpn_metrics]},

        %% 2. Routing table
        #{id => erlvpn_router,
          start => {erlvpn_router, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [erlvpn_router]},

        %% 3. IP address pool
        #{id => erlvpn_ip_pool,
          start => {erlvpn_ip_pool, start_link, [CIDR]},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [erlvpn_ip_pool]},

        %% 4. Authentication manager
        #{id => erlvpn_auth,
          start => {erlvpn_auth, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [erlvpn_auth]},

        %% 5. DNS resolver
        #{id => erlvpn_dns,
          start => {erlvpn_dns, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [erlvpn_dns]},

        %% 6. TUN device manager
        #{id => erlvpn_tun_manager,
          start => {erlvpn_tun_manager, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [erlvpn_tun_manager]},

        %% 7. Session supervisor
        #{id => erlvpn_session_sup,
          start => {erlvpn_session_sup, start_link, []},
          restart => permanent,
          shutdown => infinity,
          type => supervisor,
          modules => [erlvpn_session_sup]},

        %% 8. QUIC listener
        #{id => erlvpn_quic_listener,
          start => {erlvpn_quic_listener, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [erlvpn_quic_listener]}
    ],

    ?LOG_INFO(#{msg => "Server supervisor starting",
                children => length(Children)}),
    {ok, {SupFlags, Children}}.
