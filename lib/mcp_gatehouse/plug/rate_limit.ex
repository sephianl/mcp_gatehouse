defmodule McpGatehouse.Plug.RateLimit do
  @moduledoc """
  A per-caller ceiling on requests to one MCP surface.

      plug McpGatehouse.Plug.RateLimit, prefix: "mcp_oauth", limit: 60

  after `McpGatehouse.Plug.Server` in the pipeline, or with its own
  `server: MyAppWeb.Mcp`, which supplies the trusted proxies.

  Each surface passes its own `prefix:`, so one cannot eat another's budget.

  `key: :ip` (the default) counts by `McpGatehouse.ClientIp`, which is all a
  surface placed *ahead* of authentication can do — an unauthenticated flood has
  no other identity. `key: :actor` counts by the Ash actor's `:id` and so belongs
  after `McpGatehouse.Plug.Bearer`; it falls back to the address when no actor
  was established, so an unauthenticated request is still bounded. A denied hit
  still counts, so an `:ip` limit placed before an `:actor` one must be the
  larger of the two.

  The counter is `McpGatehouse.RateLimiter` unless `config :mcp_gatehouse,
  :rate_limiter` names another module with Hammer's `hit/3`, read per request so
  a test stub can stand in. A denied request gets 429 `{"error":"rate_limited"}`.
  """
  @behaviour Plug

  import Plug.Conn

  alias Ash.PlugHelpers
  alias McpGatehouse.ClientIp
  alias McpGatehouse.Plug.Json
  alias McpGatehouse.Plug.Options
  alias McpGatehouse.Server.Callbacks

  @schema [
    prefix: [type: :string, required: true],
    limit: [type: :pos_integer, required: true],
    window_ms: [type: :pos_integer, default: 60_000],
    key: [type: {:in, [:ip, :actor]}, default: :ip]
  ]

  @impl Plug
  @spec init(keyword()) :: map()
  def init(opts), do: Options.validate(__MODULE__, @schema, opts)

  @impl Plug
  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, %{prefix: prefix, limit: limit, window_ms: window_ms, key: key} = opts) do
    server = Options.server(conn, __MODULE__, opts)
    counter = Application.get_env(:mcp_gatehouse, :rate_limiter, McpGatehouse.RateLimiter)

    "#{prefix}:#{key_for(key, conn, server)}"
    |> counter.hit(window_ms, limit)
    |> allow(conn)
  end

  defp key_for(:ip, conn, server), do: ClientIp.resolve(conn, Callbacks.trusted_proxies(server))

  defp key_for(:actor, conn, server), do: conn |> PlugHelpers.get_actor() |> actor_key(conn, server)

  defp actor_key(%{id: id}, _conn, _server) when is_binary(id), do: "actor:#{id}"
  defp actor_key(_actor, conn, server), do: key_for(:ip, conn, server)

  defp allow({:allow, _count}, conn), do: conn

  defp allow({:deny, _retry_after}, conn) do
    conn
    |> Json.send_json(429, %{error: "rate_limited"})
    |> halt()
  end
end
