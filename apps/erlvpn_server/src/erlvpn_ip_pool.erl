%%%-------------------------------------------------------------------
%%% @doc ErlVPN IP Address Pool Manager
%%%
%%% Manages allocation and deallocation of tunnel IP addresses
%%% from a configured CIDR range. Uses a bitmap-like approach with
%%% gb_sets for efficient tracking.
%%% @end
%%%-------------------------------------------------------------------
-module(erlvpn_ip_pool).

-behaviour(gen_server).

-include_lib("erlvpn_common/include/erlvpn.hrl").
-include_lib("kernel/include/logger.hrl").

%% API
-export([start_link/1, allocate/0, allocate/1, release/1,
         is_allocated/1, available_count/0, allocated_count/0,
         get_server_ip/0, get_range/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    base_ip     :: non_neg_integer(),   %% Network address as integer
    prefix_len  :: 0..32,
    server_ip   :: inet:ip4_address(),
    first_ip    :: non_neg_integer(),   %% First allocatable (base + 2)
    last_ip     :: non_neg_integer(),   %% Last allocatable (broadcast - 1)
    next_ip     :: non_neg_integer(),   %% Next candidate for allocation
    allocated   :: gb_sets:set(non_neg_integer()),
    total       :: non_neg_integer()
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link(string()) -> {ok, pid()} | {error, term()}.
start_link(CIDR) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [CIDR], []).

-spec allocate() -> {ok, inet:ip4_address()} | {error, exhausted}.
allocate() ->
    gen_server:call(?MODULE, allocate).

-spec allocate(inet:ip4_address()) -> {ok, inet:ip4_address()} | {error, term()}.
allocate(PreferredIP) ->
    gen_server:call(?MODULE, {allocate, PreferredIP}).

-spec release(inet:ip4_address()) -> ok | {error, not_allocated}.
release(IP) ->
    gen_server:call(?MODULE, {release, IP}).

-spec is_allocated(inet:ip4_address()) -> boolean().
is_allocated(IP) ->
    gen_server:call(?MODULE, {is_allocated, IP}).

-spec available_count() -> non_neg_integer().
available_count() ->
    gen_server:call(?MODULE, available_count).

-spec allocated_count() -> non_neg_integer().
allocated_count() ->
    gen_server:call(?MODULE, allocated_count).

-spec get_server_ip() -> inet:ip4_address().
get_server_ip() ->
    gen_server:call(?MODULE, get_server_ip).

-spec get_range() -> {inet:ip4_address(), inet:ip4_address()}.
get_range() ->
    gen_server:call(?MODULE, get_range).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([CIDR]) ->
    case erlvpn_config:parse_cidr(CIDR) of
        {ok, {BaseIPTuple, PrefixLen}} ->
            BaseInt = ip_to_int(BaseIPTuple),
            HostBits = 32 - PrefixLen,
            TotalHosts = (1 bsl HostBits),
            %% Server gets base+1, clients get base+2 to broadcast-1
            ServerIP = int_to_ip(BaseInt + 1),
            FirstClient = BaseInt + 2,
            LastClient = BaseInt + TotalHosts - 2,
            Total = LastClient - FirstClient + 1,
            State = #state{
                base_ip = BaseInt,
                prefix_len = PrefixLen,
                server_ip = ServerIP,
                first_ip = FirstClient,
                last_ip = LastClient,
                next_ip = FirstClient,
                allocated = gb_sets:new(),
                total = Total
            },
            ?LOG_INFO(#{msg => "IP pool initialized",
                        cidr => CIDR,
                        server_ip => erlvpn_packet:ip_to_string(ServerIP),
                        available => Total}),
            {ok, State};
        {error, Reason} ->
            {stop, {invalid_cidr, CIDR, Reason}}
    end.

handle_call(allocate, _From, State) ->
    case do_allocate(State) of
        {ok, IP, NewState} ->
            ?LOG_DEBUG(#{msg => "IP allocated",
                         ip => erlvpn_packet:ip_to_string(IP)}),
            {reply, {ok, IP}, NewState};
        {error, exhausted} = Err ->
            ?LOG_WARNING(#{msg => "IP pool exhausted"}),
            {reply, Err, State}
    end;

handle_call({allocate, PreferredIP}, _From, State) ->
    IntIP = ip_to_int(PreferredIP),
    case can_allocate(IntIP, State) of
        true ->
            NewAllocated = gb_sets:add(IntIP, State#state.allocated),
            NewState = State#state{allocated = NewAllocated},
            ?LOG_DEBUG(#{msg => "IP allocated (preferred)",
                         ip => erlvpn_packet:ip_to_string(PreferredIP)}),
            {reply, {ok, PreferredIP}, NewState};
        false ->
            {reply, {error, unavailable}, State}
    end;

handle_call({release, IP}, _From, State) ->
    IntIP = ip_to_int(IP),
    case gb_sets:is_member(IntIP, State#state.allocated) of
        true ->
            NewAllocated = gb_sets:delete(IntIP, State#state.allocated),
            NewState = State#state{allocated = NewAllocated},
            ?LOG_DEBUG(#{msg => "IP released",
                         ip => erlvpn_packet:ip_to_string(IP)}),
            {reply, ok, NewState};
        false ->
            {reply, {error, not_allocated}, State}
    end;

handle_call({is_allocated, IP}, _From, State) ->
    IntIP = ip_to_int(IP),
    {reply, gb_sets:is_member(IntIP, State#state.allocated), State};

handle_call(available_count, _From, State) ->
    {reply, State#state.total - gb_sets:size(State#state.allocated), State};

handle_call(allocated_count, _From, State) ->
    {reply, gb_sets:size(State#state.allocated), State};

handle_call(get_server_ip, _From, State) ->
    {reply, State#state.server_ip, State};

handle_call(get_range, _From, State) ->
    First = int_to_ip(State#state.first_ip),
    Last = int_to_ip(State#state.last_ip),
    {reply, {First, Last}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%====================================================================
%% Internal
%%====================================================================

do_allocate(#state{first_ip = First, last_ip = Last, next_ip = Next,
                   allocated = Allocated, total = Total} = State) ->
    AllocSize = gb_sets:size(Allocated),
    case AllocSize >= Total of
        true ->
            {error, exhausted};
        false ->
            case find_free(Next, Last, First, Allocated, Total) of
                {ok, FreeIP} ->
                    NewAllocated = gb_sets:add(FreeIP, Allocated),
                    NewNext = case FreeIP >= Last of
                                  true -> First;
                                  false -> FreeIP + 1
                              end,
                    IP = int_to_ip(FreeIP),
                    {ok, IP, State#state{allocated = NewAllocated,
                                         next_ip = NewNext}};
                exhausted ->
                    {error, exhausted}
            end
    end.

find_free(Current, Last, First, Allocated, MaxAttempts) ->
    find_free(Current, Last, First, Allocated, MaxAttempts, 0).

find_free(_Current, _Last, _First, _Allocated, MaxAttempts, Attempts)
  when Attempts >= MaxAttempts ->
    exhausted;
find_free(Current, Last, First, Allocated, MaxAttempts, Attempts) ->
    case gb_sets:is_member(Current, Allocated) of
        false ->
            {ok, Current};
        true ->
            Next = case Current >= Last of
                       true -> First;
                       false -> Current + 1
                   end,
            find_free(Next, Last, First, Allocated, MaxAttempts, Attempts + 1)
    end.

can_allocate(IntIP, #state{first_ip = First, last_ip = Last, allocated = Allocated}) ->
    IntIP >= First andalso IntIP =< Last andalso
    not gb_sets:is_member(IntIP, Allocated).

ip_to_int({A, B, C, D}) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D.

int_to_ip(Int) ->
    {(Int bsr 24) band 16#FF,
     (Int bsr 16) band 16#FF,
     (Int bsr 8) band 16#FF,
     Int band 16#FF}.
