%%%-------------------------------------------------------------------
%%% @doc ErlVPN TUN Device Manager
%%%
%%% Manages the shared TUN device for all VPN clients. Handles
%%% reading packets from the TUN device and dispatching them
%%% to the appropriate client sessions via the routing table.
%%%
%%% Falls back to a "disabled" mock mode when tunctl is not
%%% available (useful for testing/development).
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_tun_manager).

-behaviour(gen_server).

-include_lib("erlvpn_common/include/erlvpn.hrl").
-include_lib("kernel/include/logger.hrl").

%% API
-export([start_link/0, start_link/1, write_packet/1,
         get_device_name/0, is_enabled/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    tun_ref    :: pid() | undefined,
    device     :: binary() | undefined,
    enabled    :: boolean(),
    rx_count = 0 :: non_neg_integer(),
    tx_count = 0 :: non_neg_integer()
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link([]).

-spec start_link(proplists:proplist()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

%% @doc Write a raw IP packet to the TUN device.
-spec write_packet(binary()) -> ok | {error, term()}.
write_packet(Packet) when is_binary(Packet) ->
    gen_server:cast(?MODULE, {write, Packet}).

%% @doc Get the TUN device name.
-spec get_device_name() -> binary() | undefined.
get_device_name() ->
    gen_server:call(?MODULE, get_device_name).

%% @doc Check if TUN device is active.
-spec is_enabled() -> boolean().
is_enabled() ->
    gen_server:call(?MODULE, is_enabled).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Opts) ->
    DeviceName = proplists:get_value(device,Opts,
                     erlvpn_config:get(tunnel_device, "erlvpn0")),
    case is_tunctl_available() of
        true ->
            try_create_tun(DeviceName);
        false ->
            ?LOG_WARNING(#{msg => "tunctl not available, TUN device disabled",
                           hint => "Install tunctl for full VPN functionality"}),
            {ok, #state{enabled = false}}
    end.

handle_call(get_device_name, _From, #state{device = Dev} = State) ->
    {reply, Dev, State};

handle_call(is_enabled, _From, #state{enabled = En} = State) ->
    {reply, En, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({write, Packet}, #state{enabled = true, tun_ref = Ref,
                                     tx_count = Tx} = State) ->
    case tuncer:send(Ref, Packet) of
        ok ->
            erlvpn_metrics:increment(erlvpn_packets_tx_total),
            erlvpn_metrics:increment(erlvpn_bytes_tx_total, byte_size(Packet)),
            {noreply, State#state{tx_count = Tx + 1}};
        {error, Reason} ->
            ?LOG_ERROR(#{msg => "TUN write failed", reason => Reason}),
            {noreply, State}
    end;

handle_cast({write, _Packet}, #state{enabled = false} = State) ->
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Handle packets from TUN device (active mode)
handle_info({tuntap, _Ref, Packet}, #state{rx_count = Rx} = State) ->
    erlvpn_metrics:increment(erlvpn_packets_rx_total),
    erlvpn_metrics:increment(erlvpn_bytes_rx_total, byte_size(Packet)),
    dispatch_packet(Packet),
    {noreply, State#state{rx_count = Rx + 1}};

handle_info({tuntap_error, _Ref, Reason}, State) ->
    ?LOG_ERROR(#{msg => "TUN read error", reason => Reason}),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{enabled = true, tun_ref = Ref}) ->
    ?LOG_INFO(#{msg => "Destroying TUN device"}),
    catch tuncer:destroy(Ref),
    ok;
terminate(_Reason, _State) ->
    ok.

%%====================================================================
%% Internal
%%====================================================================

try_create_tun(DeviceName) ->
    DevBin = iolist_to_binary([DeviceName]),
    try
        {ok, Ref} = tuncer:create(DevBin, [tun, no_pi, {active, true}]),
        ActualDev = tuncer:devname(Ref),
        ?LOG_INFO(#{msg => "TUN device created",
                    device => ActualDev}),
        {ok, #state{tun_ref = Ref, device = ActualDev, enabled = true}}
    catch
        Error:Reason ->
            ?LOG_ERROR(#{msg => "Failed to create TUN device",
                         device => DevBin,
                         error => Error, reason => Reason,
                         hint => "Try running with CAP_NET_ADMIN or as root"}),
            {ok, #state{enabled = false}}
    end.

dispatch_packet(Packet) ->
    case erlvpn_packet:get_dst_ip(Packet) of
        {ok, DstIP} ->
            case erlvpn_router:lookup(DstIP) of
                {ok, Pid, _Stream} ->
                    Pid ! {tunnel_packet, Packet};
                not_found ->
                    ?LOG_DEBUG(#{msg => "No route for packet",
                                 dst_ip => erlvpn_packet:ip_to_string(DstIP)})
            end;
        {error, _Reason} ->
            ?LOG_DEBUG(#{msg => "Could not parse packet destination"})
    end.

is_tunctl_available() ->
    case code:which(tuncer) of
        non_existing -> false;
        _ -> true
    end.
