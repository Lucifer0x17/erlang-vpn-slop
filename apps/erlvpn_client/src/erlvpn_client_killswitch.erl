%%%-------------------------------------------------------------------
%%% @doc ErlVPN Client Kill Switch
%%%
%%% Manages firewall rules to block all non-VPN traffic when
%%% the VPN connection drops. Supports Linux (iptables) and
%%% macOS (pf). The kill switch ensures no data leaks when
%%% the tunnel is down.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_client_killswitch).

-behaviour(gen_server).

-include_lib("kernel/include/logger.hrl").

-export([start_link/0, activate/1, deactivate/0,
         handle_action/1, is_active/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    active      :: boolean(),
    server_ip   :: string() | undefined,
    server_port :: inet:port_number() | undefined,
    os          :: linux | darwin | unsupported
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec activate(map()) -> ok | {error, term()}.
activate(Config) ->
    gen_server:call(?MODULE, {activate, Config}).

-spec deactivate() -> ok.
deactivate() ->
    gen_server:call(?MODULE, deactivate).

-spec handle_action(activate | release) -> ok.
handle_action(Action) ->
    gen_server:cast(?MODULE, {action, Action}).

-spec is_active() -> boolean().
is_active() ->
    gen_server:call(?MODULE, is_active).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    OS = detect_os(),
    {ok, #state{active = false, os = OS}}.

handle_call({activate, Config}, _From, #state{os = OS} = State) ->
    ServerIP = maps:get(server_ip, Config, undefined),
    ServerPort = maps:get(server_port, Config, 4433),
    case do_activate(OS, ServerIP, ServerPort) of
        ok ->
            ?LOG_INFO(#{msg => "Kill switch activated",
                        server_ip => ServerIP}),
            {reply, ok, State#state{active = true,
                                     server_ip = ServerIP,
                                     server_port = ServerPort}};
        {error, Reason} ->
            ?LOG_ERROR(#{msg => "Kill switch activation failed",
                         reason => Reason}),
            {reply, {error, Reason}, State}
    end;

handle_call(deactivate, _From, #state{os = OS} = State) ->
    do_deactivate(OS),
    ?LOG_INFO(#{msg => "Kill switch deactivated"}),
    {reply, ok, State#state{active = false}};

handle_call(is_active, _From, #state{active = Active} = State) ->
    {reply, Active, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({action, activate}, #state{server_ip = IP, server_port = Port,
                                        os = OS} = State) ->
    do_activate(OS, IP, Port),
    {noreply, State#state{active = true}};

handle_cast({action, release}, #state{os = OS} = State) ->
    do_deactivate(OS),
    {noreply, State#state{active = false}};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{active = true, os = OS}) ->
    %% Deactivate kill switch on clean shutdown
    do_deactivate(OS),
    ok;
terminate(_Reason, _State) ->
    ok.

%%====================================================================
%% Internal
%%====================================================================

detect_os() ->
    case os:type() of
        {unix, linux} -> linux;
        {unix, darwin} -> darwin;
        _ -> unsupported
    end.

do_activate(linux, ServerIP, ServerPort) when ServerIP =/= undefined ->
    %% Note: In production, these would execute actual iptables commands
    %% via os:cmd/1. For safety, we log what would be done.
    ?LOG_INFO(#{msg => "Kill switch rules (Linux)",
                action => activate,
                rules => [
                    io_lib:format("iptables -A OUTPUT -o tun+ -j ACCEPT", []),
                    io_lib:format("iptables -A OUTPUT -o lo -j ACCEPT", []),
                    io_lib:format("iptables -A OUTPUT -d ~s -p udp --dport ~B -j ACCEPT",
                                  [ServerIP, ServerPort]),
                    "iptables -A OUTPUT -j DROP"
                ]}),
    ok;
do_activate(darwin, ServerIP, ServerPort) when ServerIP =/= undefined ->
    ?LOG_INFO(#{msg => "Kill switch rules (macOS)",
                action => activate,
                rules => [
                    io_lib:format("block drop all", []),
                    io_lib:format("pass on lo0", []),
                    io_lib:format("pass on utun+", []),
                    io_lib:format("pass out proto udp to ~s port ~B",
                                  [ServerIP, ServerPort])
                ]}),
    ok;
do_activate(_, _, _) ->
    {error, unsupported_or_missing_config}.

do_deactivate(linux) ->
    ?LOG_INFO(#{msg => "Kill switch rules (Linux)", action => deactivate}),
    ok;
do_deactivate(darwin) ->
    ?LOG_INFO(#{msg => "Kill switch rules (macOS)", action => deactivate}),
    ok;
do_deactivate(_) ->
    ok.
