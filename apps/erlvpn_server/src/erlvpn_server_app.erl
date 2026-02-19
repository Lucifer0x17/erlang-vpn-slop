%%%-------------------------------------------------------------------
%%% @doc ErlVPN Server Application
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_server_app).

-behaviour(application).

-include_lib("erlvpn_common/include/erlvpn.hrl").
-include_lib("kernel/include/logger.hrl").

-export([start/2, stop/1]).

%%====================================================================
%% Application callbacks
%%====================================================================

start(_StartType, _StartArgs) ->
    ?LOG_INFO(#{msg => "ErlVPN Server starting",
                version => ?ERLVPN_VERSION}),
    erlvpn_server_sup:start_link().

stop(_State) ->
    ?LOG_INFO(#{msg => "ErlVPN Server stopping"}),
    ok.
