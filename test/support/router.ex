defmodule McpGatehouse.Test.OAuthRoute do
  @moduledoc """
  The host's `:mcp_oauth` pipeline in front of one library route plug:
  `McpGatehouse.Plug.Server` first, then the rate limit and the route plug, the
  last two without a `server:` of their own.
  """
  @behaviour Plug

  @impl true
  def init({plug, opts}) do
    Enum.map(
      [
        {McpGatehouse.Plug.Server, server: McpGatehouse.Test.Server},
        {McpGatehouse.Plug.RateLimit, prefix: "mcp_oauth", limit: 60},
        {plug, opts}
      ],
      fn {module, module_opts} -> {module, module.init(module_opts)} end
    )
  end

  @impl true
  def call(conn, plugs) do
    Enum.reduce_while(plugs, conn, fn {plug, opts}, acc ->
      case plug.call(acc, opts) do
        %Plug.Conn{halted: true} = halted -> {:halt, halted}
        continued -> {:cont, continued}
      end
    end)
  end
end

defmodule McpGatehouse.Test.McpPipeline do
  @moduledoc """
  The host's `:mcp` pipeline and `AshAi.Mcp.Router` forward. `Plug.Builder`
  initialises these plugs at compile time, as a production Phoenix router does.
  Only `McpGatehouse.Plug.Server` names the server.
  """
  use Plug.Builder

  plug McpGatehouse.Plug.Server, server: McpGatehouse.Test.Server
  plug McpGatehouse.Plug.RateLimit, prefix: "mcp", limit: 600
  plug McpGatehouse.Plug.Bearer
  plug McpGatehouse.Plug.Analytics

  plug AshAi.Mcp.Router,
    tools: [:list_widgets, :report_missing_capability],
    otp_app: :mcp_gatehouse,
    mcp_name: "Test MCP"
end

defmodule McpGatehouse.Test.Router do
  @moduledoc """
  A host router mounting every library plug the way the README wires them into
  Phoenix: the discovery and OAuth endpoints behind the `:mcp_oauth` pipeline,
  and `/mcp` through `McpGatehouse.Test.McpPipeline`. No route plug is given
  `server:`, so every test through this router runs them on the server
  `McpGatehouse.Plug.Server` put on the connection.

  The consent routes are the host's own controller and are exercised through
  `McpGatehouse.OAuth.Authorization` directly.
  """
  use Plug.Router

  alias McpGatehouse.Plug.Metadata
  alias McpGatehouse.Plug.Registration
  alias McpGatehouse.Plug.Revocation
  alias McpGatehouse.Plug.Token
  alias McpGatehouse.Test.OAuthRoute

  plug Plug.Parsers, parsers: [:urlencoded, :json], pass: ["*/*"], json_decoder: Jason
  plug :match
  plug :dispatch

  get "/.well-known/oauth-protected-resource",
    to: OAuthRoute,
    init_opts: {Metadata, document: :protected_resource}

  get "/.well-known/oauth-authorization-server",
    to: OAuthRoute,
    init_opts: {Metadata, document: :authorization_server}

  post "/mcp/oauth/register", to: OAuthRoute, init_opts: {Registration, []}
  post "/mcp/oauth/token", to: OAuthRoute, init_opts: {Token, []}
  post "/mcp/oauth/revoke", to: OAuthRoute, init_opts: {Revocation, []}

  forward "/mcp", to: McpGatehouse.Test.McpPipeline

  match _ do
    send_resp(conn, 404, "")
  end
end
