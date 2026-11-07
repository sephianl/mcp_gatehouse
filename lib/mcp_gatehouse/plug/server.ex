defmodule McpGatehouse.Plug.Server do
  @moduledoc """
  Names the host's `McpGatehouse.Server` once per pipeline, so the library plugs
  after it — the route plugs included — need no `server:` option of their own.

      pipeline :mcp_oauth do
        plug McpGatehouse.Plug.Server, server: MyAppWeb.Mcp
        ...
      end

      post "/token", McpGatehouse.Plug.Token, []

  Phoenix escapes a route's plug options into the router at compile time, so
  `server: MyAppWeb.Mcp` on a route gives the router a compile-time dependency on
  the server module, and through it a compile-connected one on everything that
  module reaches: the endpoint, the resources, the user lookup. `mix xref` then
  reports compile-connected cycles, and editing any of those files recompiles the
  router and whatever depends on it at compile time. Under `plug_init_mode:
  :runtime` (what Phoenix hosts set in dev and test) a pipeline plug's options
  are only a runtime reference, so the server is named here and read back from
  the connection. Prod's `:compile` mode makes it compile-time again, which only
  costs a one-off release build.

  A plug's own `server:` still takes precedence over this one. A library plug
  that finds neither raises `ArgumentError` per request; see
  `McpGatehouse.Plug.Options.server/3`.
  """
  @behaviour Plug

  alias McpGatehouse.Plug.Options

  @schema [server: [type: {:custom, Options, :validate_server, []}, required: true]]

  @impl Plug
  @spec init(keyword()) :: map()
  def init(opts), do: Options.validate(__MODULE__, @schema, opts)

  @impl Plug
  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, %{server: server}), do: Options.put_server(conn, server)
end
