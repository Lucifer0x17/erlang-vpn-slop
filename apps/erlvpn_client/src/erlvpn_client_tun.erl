%%%-------------------------------------------------------------------
%%% @doc ErlVPN Client TUN Device Manager
%%%
%%% Manages the client-side TUN device, configures routes,
%%% and handles incoming packets from the TUN device.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_client_tun).

-behaviour(gen_server).

-include_lib("erlvpn_common/include/erlvpn.hrl").
-include_lib("kernel/include/logger.hrl").

-export([start_link/0, configure/2, update_routes/2,
         write_packet/1, is_configured/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    tun_ref   :: pid() | undefined,
    device    :: binary() | undefined,
    tunnel_ip :: inet:ip4_address() | undefined,
    mtu       :: pos_integer(),
    enabled   :: boolean()
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec configure(inet:ip4_address(), pos_integer()) -> ok | {error, term()}.
configure(TunnelIP, MTU) ->
    gen_server:call(?MODULE, {configure, TunnelIP, MTU}).

-spec update_routes([string()], [string()]) -> ok.
update_routes(Add, Remove) ->
    gen_server:cast(?MODULE, {update_routes, Add, Remove}).

-spec write_packet(binary()) -> ok.
write_packet(Packet) ->
    gen_server:cast(?MODULE, {write, Packet}).

-spec is_configured() -> boolean().
is_configured() ->
    gen_server:call(?MODULE, is_configured).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    {ok, #state{mtu = 1280, enabled = false}}.

handle_call({configure, TunnelIP, MTU}, _From, State) ->
    case setup_tun(TunnelIP, MTU) of
        {ok, NewState} ->
            ?LOG_INFO(#{msg => "Client TUN configured",
                        tunnel_ip => erlvpn_packet:ip_to_string(TunnelIP),
                        mtu => MTU}),
            {reply, ok, NewState};
        {error, Reason} ->
            ?LOG_ERROR(#{msg => "Failed to configure TUN", reason => Reason}),
            {reply, {error, Reason}, State}
    end;

handle_call(is_configured, _From, #state{enabled = E} = State) ->
    {reply, E, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({write, Packet}, #state{enabled = true, tun_ref = Ref} = State) ->
    catch tuncer:send(Ref, Packet),
    {noreply, State};

handle_cast({write, _}, State) ->
    {noreply, State};

handle_cast({update_routes, Add, Remove}, State) ->
    ?LOG_INFO(#{msg => "Route update", add => Add, remove => Remove}),
    %% In a real implementation, this would modify the OS routing table
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({tuntap, _Ref, Packet}, State) ->
    %% Forward packet from TUN to VPN connection
    erlvpn_client_conn:send_packet(Packet),
    {noreply, State};

handle_info({tuntap_error, _Ref, Reason}, State) ->
    ?LOG_ERROR(#{msg => "Client TUN read error", reason => Reason}),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{tun_ref = Ref, enabled = true}) ->
    catch tuncer:destroy(Ref),
    ok;
terminate(_Reason, _State) ->
    ok.

%%====================================================================
%% Internal
%%====================================================================

setup_tun(TunnelIP, MTU) ->
    case code:which(tuncer) of
        non_existing ->
            ?LOG_WARNING(#{msg => "tunctl not available, TUN disabled"}),
            {ok, #state{tunnel_ip = TunnelIP, mtu = MTU, enabled = false}};
        _ ->
            try
                {ok, Ref} = tuncer:create(<<>>, [tun, no_pi, {active, true}]),
                Dev = tuncer:devname(Ref),
                IPStr = erlvpn_packet:ip_to_string(TunnelIP),
                tuncer:up(Ref, IPStr),
                {ok, #state{tun_ref = Ref, device = Dev,
                            tunnel_ip = TunnelIP, mtu = MTU,
                            enabled = true}}
            catch
                _:Reason ->
                    {error, Reason}
            end
    end.
