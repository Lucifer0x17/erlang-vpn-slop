%%%-------------------------------------------------------------------
%%% @doc ErlVPN Client Packet Forwarder
%%%
%%% Bridges packets between the local TUN device and the
%%% QUIC connection to the VPN server.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_client_forwarder).

-behaviour(gen_server).

-include_lib("kernel/include/logger.hrl").

-export([start_link/0, tunnel_up/2, tunnel_down/0,
         from_server/1, from_tun/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    tunnel_ip   :: inet:ip4_address() | undefined,
    data_stream :: reference() | undefined,
    active      :: boolean(),
    rx_count = 0 :: non_neg_integer(),
    tx_count = 0 :: non_neg_integer()
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Called when the VPN tunnel is established.
-spec tunnel_up(inet:ip4_address(), reference() | undefined) -> ok.
tunnel_up(TunnelIP, DataStream) ->
    gen_server:cast(?MODULE, {tunnel_up, TunnelIP, DataStream}).

%% @doc Called when the VPN tunnel goes down.
-spec tunnel_down() -> ok.
tunnel_down() ->
    gen_server:cast(?MODULE, tunnel_down).

%% @doc Handle a packet received from the VPN server.
-spec from_server(binary()) -> ok.
from_server(Packet) ->
    gen_server:cast(?MODULE, {from_server, Packet}).

%% @doc Handle a packet from the local TUN device.
-spec from_tun(binary()) -> ok.
from_tun(Packet) ->
    gen_server:cast(?MODULE, {from_tun, Packet}).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    {ok, #state{active = false}}.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({tunnel_up, TunnelIP, DataStream}, State) ->
    ?LOG_INFO(#{msg => "Forwarder activated", tunnel_ip => TunnelIP}),
    {noreply, State#state{tunnel_ip = TunnelIP,
                          data_stream = DataStream,
                          active = true}};

handle_cast(tunnel_down, State) ->
    ?LOG_INFO(#{msg => "Forwarder deactivated"}),
    {noreply, State#state{active = false, data_stream = undefined}};

handle_cast({from_server, Packet}, #state{active = true, rx_count = Rx} = State) ->
    %% Write packet to TUN device (towards local network)
    erlvpn_client_tun:write_packet(Packet),
    {noreply, State#state{rx_count = Rx + 1}};

handle_cast({from_server, _}, State) ->
    {noreply, State};

handle_cast({from_tun, Packet}, #state{active = true, tx_count = Tx} = State) ->
    %% Send packet to VPN server
    erlvpn_client_conn:send_packet(Packet),
    {noreply, State#state{tx_count = Tx + 1}};

handle_cast({from_tun, _}, State) ->
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.
