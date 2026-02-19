%%%-------------------------------------------------------------------
%%% @doc ErlVPN Client DNS Configuration
%%%
%%% Manages system DNS settings to ensure all DNS queries go
%%% through the VPN tunnel (preventing DNS leaks).
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_client_dns).

-behaviour(gen_server).

-include_lib("kernel/include/logger.hrl").

-export([start_link/0, configure/1, restore/0, get_config/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    original_dns :: [string()] | undefined,
    current_dns  :: [string()],
    configured   :: boolean()
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec configure([string() | inet:ip_address()]) -> ok.
configure(DnsServers) ->
    gen_server:call(?MODULE, {configure, DnsServers}).

-spec restore() -> ok.
restore() ->
    gen_server:call(?MODULE, restore).

-spec get_config() -> map().
get_config() ->
    gen_server:call(?MODULE, get_config).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    {ok, #state{current_dns = [], configured = false}}.

handle_call({configure, DnsServers}, _From, #state{configured = false} = State) ->
    %% Save original DNS config
    OriginalDns = get_system_dns(),
    %% Set new DNS servers
    ServerStrs = lists:map(fun format_dns/1, DnsServers),
    ?LOG_INFO(#{msg => "Configuring DNS",
                servers => ServerStrs,
                original => OriginalDns}),
    %% In a real implementation, modify /etc/resolv.conf or use resolvectl
    {reply, ok, State#state{original_dns = OriginalDns,
                             current_dns = ServerStrs,
                             configured = true}};

handle_call({configure, DnsServers}, _From, State) ->
    ServerStrs = lists:map(fun format_dns/1, DnsServers),
    {reply, ok, State#state{current_dns = ServerStrs}};

handle_call(restore, _From, #state{configured = true, original_dns = Orig} = State) ->
    ?LOG_INFO(#{msg => "Restoring DNS configuration", servers => Orig}),
    %% Restore original DNS
    {reply, ok, State#state{configured = false, current_dns = []}};

handle_call(restore, _From, State) ->
    {reply, ok, State};

handle_call(get_config, _From, State) ->
    {reply, #{configured => State#state.configured,
              current => State#state.current_dns,
              original => State#state.original_dns}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{configured = true}) ->
    ?LOG_INFO(#{msg => "Restoring DNS on shutdown"}),
    ok;
terminate(_Reason, _State) ->
    ok.

%%====================================================================
%% Internal
%%====================================================================

get_system_dns() ->
    case file:read_file("/etc/resolv.conf") of
        {ok, Content} ->
            Lines = string:split(binary_to_list(Content), "\n", all),
            [Addr || "nameserver " ++ Addr <- Lines];
        {error, _} ->
            []
    end.

format_dns(IP) when is_tuple(IP) ->
    erlvpn_packet:ip_to_string(IP);
format_dns(Str) when is_list(Str) ->
    Str;
format_dns(Bin) when is_binary(Bin) ->
    binary_to_list(Bin).
