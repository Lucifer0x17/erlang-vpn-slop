%%%-------------------------------------------------------------------
%%% @doc ErlVPN Client Application
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_client_app).

-behaviour(application).

-include_lib("kernel/include/logger.hrl").

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    ?LOG_INFO(#{msg => "ErlVPN Client starting"}),
    erlvpn_client_sup:start_link().

stop(_State) ->
    ?LOG_INFO(#{msg => "ErlVPN Client stopping"}),
    ok.
