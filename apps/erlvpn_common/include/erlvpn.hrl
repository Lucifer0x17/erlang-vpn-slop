%% ErlVPN - Shared header definitions
%% Common records, macros, and types used across server and client

-ifndef(ERLVPN_HRL).
-define(ERLVPN_HRL, true).

%%--------------------------------------------------------------------
%% Version
%%--------------------------------------------------------------------
-define(ERLVPN_VERSION, "0.1.0").
-define(ERLVPN_ALPN, "erlvpn").

%%--------------------------------------------------------------------
%% Control Protocol Message Types
%%--------------------------------------------------------------------
-define(MSG_AUTH_REQUEST,     16#01).
-define(MSG_AUTH_RESPONSE,    16#02).
-define(MSG_CONFIG_PUSH,      16#03).
-define(MSG_KEEPALIVE,        16#04).
-define(MSG_KEEPALIVE_ACK,    16#05).
-define(MSG_DISCONNECT,       16#06).
-define(MSG_BANDWIDTH_REPORT, 16#07).
-define(MSG_ROUTE_UPDATE,     16#08).
-define(MSG_DNS_CONFIG,       16#09).
-define(MSG_KILL_SWITCH,      16#0A).
-define(MSG_SESSION_RESUME,   16#0B).
-define(MSG_ERROR,            16#FF).

%%--------------------------------------------------------------------
%% Auth Methods
%%--------------------------------------------------------------------
-define(AUTH_TOKEN,       token).
-define(AUTH_CERTIFICATE, certificate).
-define(AUTH_PASSWORD,    password).

%%--------------------------------------------------------------------
%% Error Codes
%%--------------------------------------------------------------------
-define(ERR_AUTH_FAILED,      16#01).
-define(ERR_AUTH_TIMEOUT,     16#02).
-define(ERR_MAX_CLIENTS,      16#03).
-define(ERR_INTERNAL,         16#04).
-define(ERR_PROTOCOL,         16#05).
-define(ERR_SESSION_EXPIRED,  16#06).
-define(ERR_IP_EXHAUSTED,     16#07).
-define(ERR_INVALID_PACKET,   16#08).

%%--------------------------------------------------------------------
%% Disconnect Reasons
%%--------------------------------------------------------------------
-define(DISCONNECT_NORMAL,    normal).
-define(DISCONNECT_TIMEOUT,   timeout).
-define(DISCONNECT_AUTH_FAIL,  auth_failed).
-define(DISCONNECT_ADMIN,     admin).
-define(DISCONNECT_ERROR,     error).

%%--------------------------------------------------------------------
%% Records
%%--------------------------------------------------------------------

%% Client session state
-record(session, {
    id            :: binary(),
    client_id     :: binary() | undefined,
    tunnel_ip     :: inet:ip4_address() | undefined,
    tunnel_ip6    :: inet:ip6_address() | undefined,
    quic_conn     :: reference() | undefined,
    ctrl_stream   :: reference() | undefined,
    data_stream   :: reference() | undefined,
    auth_method   :: atom(),
    connected_at  :: integer() | undefined,
    last_activity :: integer() | undefined,
    rx_bytes = 0  :: non_neg_integer(),
    tx_bytes = 0  :: non_neg_integer(),
    rx_packets = 0 :: non_neg_integer(),
    tx_packets = 0 :: non_neg_integer()
}).

%% Server configuration
-record(server_config, {
    listen_port = 4433       :: inet:port_number(),
    listen_address = "0.0.0.0" :: string(),
    max_clients = 10000      :: pos_integer(),
    cert_file                :: string(),
    key_file                 :: string(),
    tunnel_ipv4_cidr = "10.8.0.0/16" :: string(),
    tunnel_ipv6_cidr         :: string() | undefined,
    tunnel_mtu = 1280        :: pos_integer(),
    allowed_ips = ["0.0.0.0/0"] :: [string()],
    excluded_ips = []        :: [string()],
    allow_client_to_client = false :: boolean(),
    enable_nat = true        :: boolean(),
    dns_enabled = true       :: boolean(),
    dns_upstream = ["1.1.1.1", "8.8.8.8"] :: [string()],
    auth_method = token      :: atom(),
    token_file               :: string() | undefined,
    session_token_ttl = 86400 :: pos_integer(),
    keepalive_interval = 25  :: pos_integer(),
    keepalive_timeout = 60   :: pos_integer()
}).

%% Client configuration
-record(client_config, {
    server_address = "127.0.0.1" :: string(),
    server_port = 4433       :: inet:port_number(),
    transport_mode = quic_stream :: quic_stream | quic_datagram | http3,
    auth_method = token      :: atom(),
    auth_token               :: string() | undefined,
    cert_file                :: string() | undefined,
    key_file                 :: string() | undefined,
    kill_switch = true       :: boolean(),
    kill_switch_mode = system :: system | app,
    mtu = 1280               :: pos_integer(),
    reconnect_attempts = 10  :: pos_integer(),
    reconnect_backoff_max = 30000 :: pos_integer(),
    enable_0rtt = true       :: boolean()
}).

%% Route entry
-record(route, {
    tunnel_ip     :: inet:ip4_address(),
    client_pid    :: pid(),
    quic_stream   :: reference(),
    connected_at  :: integer(),
    metadata = #{} :: map()
}).

%%--------------------------------------------------------------------
%% Default Tunnel Subnet
%%--------------------------------------------------------------------
-define(DEFAULT_TUNNEL_IP, {10, 8, 0, 1}).
-define(DEFAULT_TUNNEL_MASK, {255, 255, 0, 0}).
-define(DEFAULT_TUNNEL_CIDR, "10.8.0.0/16").

%%--------------------------------------------------------------------
%% Limits
%%--------------------------------------------------------------------
-define(MAX_PACKET_SIZE, 65535).
-define(CONTROL_FRAME_MAX_LEN, 65535).
-define(MAX_AUTH_ATTEMPTS, 5).
-define(AUTH_TIMEOUT_MS, 30000).

%%--------------------------------------------------------------------
%% ETS Table Names
%%--------------------------------------------------------------------
-define(ROUTE_TABLE, erlvpn_routes).
-define(SESSION_TABLE, erlvpn_sessions).
-define(METRICS_TABLE, erlvpn_metrics).
-define(DNS_CACHE_TABLE, erlvpn_dns_cache).
-define(TOKEN_TABLE, erlvpn_tokens).

-endif. %% ERLVPN_HRL
