%%%-------------------------------------------------------------------
%%% @doc ErlVPN Configuration Manager
%%%
%%% Loads configuration from OTP application env and provides
%%% validation and parsing utilities. Pure functional module.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_config).

-include_lib("erlvpn_common/include/erlvpn.hrl").

-export([load/0, load/1, get/1, get/2,
         validate/1, parse_cidr/1, parse_ip/1, to_map/1]).

%%====================================================================
%% API
%%====================================================================

%% @doc Load server config from application environment.
-spec load() -> {ok, #server_config{}} | {error, [term()]}.
load() ->
    load([]).

%% @doc Load server config with overrides.
-spec load(proplists:proplist() | map()) -> {ok, #server_config{}} | {error, [term()]}.
load(Overrides) when is_map(Overrides) ->
    load(maps:to_list(Overrides));
load(Overrides) when is_list(Overrides) ->
    Config = #server_config{
        listen_port        = get_opt(listen_port, Overrides, 4433),
        listen_address     = get_opt(listen_address, Overrides, "0.0.0.0"),
        max_clients        = get_opt(max_clients, Overrides, 10000),
        cert_file          = get_opt(cert_file, Overrides, undefined),
        key_file           = get_opt(key_file, Overrides, undefined),
        tunnel_ipv4_cidr   = get_opt(tunnel_ipv4_cidr, Overrides, "10.8.0.0/16"),
        tunnel_ipv6_cidr   = get_opt(tunnel_ipv6_cidr, Overrides, undefined),
        tunnel_mtu         = get_opt(tunnel_mtu, Overrides, 1280),
        allowed_ips        = get_opt(allowed_ips, Overrides, ["0.0.0.0/0"]),
        excluded_ips       = get_opt(excluded_ips, Overrides, []),
        allow_client_to_client = get_opt(allow_client_to_client, Overrides, false),
        enable_nat         = get_opt(enable_nat, Overrides, true),
        dns_enabled        = get_opt(dns_enabled, Overrides, true),
        dns_upstream       = get_opt(dns_upstream, Overrides, ["1.1.1.1", "8.8.8.8"]),
        auth_method        = get_opt(auth_method, Overrides, token),
        token_file         = get_opt(token_file, Overrides, undefined),
        session_token_ttl  = get_opt(session_token_ttl, Overrides, 86400),
        keepalive_interval = get_opt(keepalive_interval, Overrides, 25),
        keepalive_timeout  = get_opt(keepalive_timeout, Overrides, 60)
    },
    case validate(Config) of
        ok -> {ok, Config};
        {error, _} = Err -> Err
    end.

%% @doc Get a single config value from application env.
-spec get(atom()) -> term().
get(Key) ->
    get(Key, undefined).

%% @doc Get a single config value with default.
-spec get(atom(), term()) -> term().
get(Key, Default) ->
    application:get_env(erlvpn_server, Key, Default).

%%====================================================================
%% Validation
%%====================================================================

%% @doc Validate a server_config record.
-spec validate(#server_config{}) -> ok | {error, [term()]}.
validate(#server_config{} = C) ->
    Errors = lists:flatten([
        validate_port(C#server_config.listen_port),
        validate_positive(max_clients, C#server_config.max_clients),
        validate_cidr(C#server_config.tunnel_ipv4_cidr),
        validate_mtu(C#server_config.tunnel_mtu),
        validate_positive(session_token_ttl, C#server_config.session_token_ttl),
        validate_positive(keepalive_interval, C#server_config.keepalive_interval),
        validate_positive(keepalive_timeout, C#server_config.keepalive_timeout),
        validate_auth_method(C#server_config.auth_method)
    ]),
    case Errors of
        [] -> ok;
        _ -> {error, Errors}
    end.

%%====================================================================
%% Parsing Utilities
%%====================================================================

%% @doc Parse a CIDR string to {BaseIP, PrefixLen}.
-spec parse_cidr(string()) -> {ok, {inet:ip4_address(), 0..32}} | {error, term()}.
parse_cidr(CIDR) when is_list(CIDR) ->
    case string:split(CIDR, "/") of
        [IPStr, MaskStr] ->
            case {parse_ip(IPStr), catch list_to_integer(MaskStr)} of
                {{ok, IP}, Mask} when is_integer(Mask), Mask >= 0, Mask =< 32 ->
                    {ok, {IP, Mask}};
                {{ok, _IP}, _} ->
                    {error, {invalid_prefix_length, MaskStr}};
                {{error, Reason}, _} ->
                    {error, {invalid_ip, Reason}}
            end;
        _ ->
            {error, {invalid_cidr, CIDR}}
    end.

%% @doc Parse an IP string to a tuple.
-spec parse_ip(string()) -> {ok, inet:ip4_address() | inet:ip6_address()} | {error, term()}.
parse_ip(IPStr) when is_list(IPStr) ->
    case inet:parse_address(IPStr) of
        {ok, IP} -> {ok, IP};
        {error, Reason} -> {error, {invalid_ip, IPStr, Reason}}
    end.

%% @doc Convert server_config record to map.
-spec to_map(#server_config{}) -> map().
to_map(#server_config{} = C) ->
    #{listen_port => C#server_config.listen_port,
      listen_address => C#server_config.listen_address,
      max_clients => C#server_config.max_clients,
      cert_file => C#server_config.cert_file,
      key_file => C#server_config.key_file,
      tunnel_ipv4_cidr => C#server_config.tunnel_ipv4_cidr,
      tunnel_ipv6_cidr => C#server_config.tunnel_ipv6_cidr,
      tunnel_mtu => C#server_config.tunnel_mtu,
      allowed_ips => C#server_config.allowed_ips,
      excluded_ips => C#server_config.excluded_ips,
      allow_client_to_client => C#server_config.allow_client_to_client,
      enable_nat => C#server_config.enable_nat,
      dns_enabled => C#server_config.dns_enabled,
      dns_upstream => C#server_config.dns_upstream,
      auth_method => C#server_config.auth_method,
      token_file => C#server_config.token_file,
      session_token_ttl => C#server_config.session_token_ttl,
      keepalive_interval => C#server_config.keepalive_interval,
      keepalive_timeout => C#server_config.keepalive_timeout}.

%%====================================================================
%% Internal
%%====================================================================

get_opt(Key, Overrides, Default) ->
    case proplists:get_value(Key, Overrides) of
        undefined -> application:get_env(erlvpn_server, Key, Default);
        Value -> Value
    end.

validate_port(Port) when is_integer(Port), Port > 0, Port =< 65535 -> [];
validate_port(Port) -> [{invalid_port, Port}].

validate_positive(_Name, V) when is_integer(V), V > 0 -> [];
validate_positive(Name, V) -> [{invalid_positive, Name, V}].

validate_cidr(CIDR) ->
    case parse_cidr(CIDR) of
        {ok, _} -> [];
        {error, Reason} -> [{invalid_cidr, CIDR, Reason}]
    end.

validate_mtu(MTU) when is_integer(MTU), MTU >= 576, MTU =< 9000 -> [];
validate_mtu(MTU) -> [{invalid_mtu, MTU}].

validate_auth_method(token) -> [];
validate_auth_method(certificate) -> [];
validate_auth_method(password) -> [];
validate_auth_method(M) -> [{invalid_auth_method, M}].
