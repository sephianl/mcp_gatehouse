defmodule McpGatehouse.Test.PhoenixRouter do
  @moduledoc """
  README §4's router, compiled by Phoenix's own route and pipeline macros, with
  `McpGatehouse.Test.Server` for `MyAppWeb.Mcp`, `:mcp_gatehouse` for `:my_app`
  and `"Test MCP"` for `"My App"`. The consent pipeline and scope are left out:
  they route to the host's own controller.

  `McpGatehouse.PhoenixRouterTest` checks that README §4 and the `McpGatehouse`
  overview wire the library exactly as this module does, so a change to a plug's
  options that breaks this router breaks the documented wiring too.
  """
  use Phoenix.Router, helpers: false

  import Phoenix.Controller
  import Plug.Conn

  alias McpGatehouse.Plug.Metadata
  alias McpGatehouse.Plug.RateLimit
  alias McpGatehouse.Plug.Server

  @mcp_tools [:list_widgets, :report_missing_capability]

  pipeline :mcp_oauth do
    plug Server, server: McpGatehouse.Test.Server
    plug :accepts, ["json"]
    plug RateLimit, prefix: "mcp_oauth", limit: 60
  end

  pipeline :mcp do
    plug Server, server: McpGatehouse.Test.Server
    plug :accepts, ["json"]
    plug RateLimit, prefix: "mcp", limit: 600
    plug McpGatehouse.Plug.Bearer
    plug McpGatehouse.Plug.Analytics
  end

  scope "/.well-known" do
    pipe_through :mcp_oauth

    get "/oauth-protected-resource", Metadata, document: :protected_resource
    get "/oauth-authorization-server", Metadata, document: :authorization_server
  end

  scope "/mcp/oauth" do
    pipe_through :mcp_oauth

    post "/register", McpGatehouse.Plug.Registration, []
    post "/token", McpGatehouse.Plug.Token, []
    post "/revoke", McpGatehouse.Plug.Revocation, []
  end

  scope "/mcp" do
    pipe_through :mcp

    forward "/", AshAi.Mcp.Router,
      tools: @mcp_tools,
      otp_app: :mcp_gatehouse,
      mcp_name: "Test MCP"
  end
end

defmodule McpGatehouse.Test.PhoenixEndpoint do
  @moduledoc "The part of a host endpoint the router relies on: body parsing in front of it."
  use Plug.Builder

  plug Plug.Parsers, parsers: [:urlencoded, :json], pass: ["*/*"], json_decoder: Jason
  plug McpGatehouse.Test.PhoenixRouter
end
