defmodule McpGatehouse.Plug.ServerTest do
  @moduledoc """
  A host names its server once, with `McpGatehouse.Plug.Server` at the top of a
  pipeline, so no route's options give its router a compile-time reference to
  it. Every library plug then finds the server on the connection, still prefers
  its own `server:`, and refuses to run with neither — `Bearer` above all, which
  must never let an unconfigured request through.

  `McpGatehouse.Test.Router` is wired this way, so the rest of the suite runs
  the route and pipeline plugs on the connection's server too.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias McpGatehouse.Plug.Analytics
  alias McpGatehouse.Plug.Bearer
  alias McpGatehouse.Plug.Metadata
  alias McpGatehouse.Plug.RateLimit
  alias McpGatehouse.Plug.Registration
  alias McpGatehouse.Plug.Revocation
  alias McpGatehouse.Plug.Server
  alias McpGatehouse.Plug.Token
  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.User

  defmodule OtherEndpoint do
    @moduledoc "An endpoint at another URL, so a document shows which server built it."

    @spec url() :: String.t()
    def url, do: "https://other.example.test"

    @spec path(String.t()) :: String.t()
    def path(path), do: path
  end

  defmodule OtherServer do
    @moduledoc "The test host's server, served from `OtherEndpoint`."
    @behaviour McpGatehouse.Server

    alias McpGatehouse.Test.Server

    @impl true
    defdelegate otp_app, to: Server
    @impl true
    defdelegate server_name, to: Server
    @impl true
    def endpoint, do: OtherEndpoint
    @impl true
    defdelegate client_resource, to: Server
    @impl true
    defdelegate authorization_code_resource, to: Server
    @impl true
    defdelegate access_token_resource, to: Server
    @impl true
    defdelegate load_user(user_id, company_id), to: Server
    @impl true
    defdelegate consent_identity(user), to: Server
    @impl true
    defdelegate capture_event(event, distinct_id, company_id, properties),
      to: Server
  end

  defmodule UnconfiguredMcpPipeline do
    @moduledoc "An `:mcp` pipeline missing `McpGatehouse.Plug.Server`, reporting whether a request got past `Bearer`."
    use Plug.Builder

    plug Bearer
    plug :reached

    defp reached(conn, _opts) do
      send(self(), :reached_past_bearer)
      conn
    end
  end

  @route_plugs [
    {Metadata, [document: :protected_resource]},
    {Registration, []},
    {Token, []},
    {Revocation, []}
  ]

  @pipeline_plugs [
    {RateLimit, [prefix: "mcp", limit: 1]},
    {Bearer, []},
    {Analytics, []}
  ]

  defp on_server(conn, server), do: Server.call(conn, Server.init(server: server))

  defp run(conn, plug, opts), do: plug.call(conn, plug.init(opts))

  test "puts the server on the connection" do
    conn = :get |> conn("/") |> on_server(OtherServer)

    assert conn.private.mcp_gatehouse_server == OtherServer
  end

  test "requires a module" do
    assert_raise ArgumentError, ~r/McpGatehouse.Plug.Server.*server/, fn -> Server.init([]) end
    assert_raise ArgumentError, ~r/expected a module/, fn -> Server.init(server: nil) end

    assert_raise ArgumentError, ~r/expected a module/, fn ->
      Server.init(server: "MyAppWeb.Mcp")
    end
  end

  test "the route plugs run on the connection's server" do
    resource =
      :get
      |> conn("/")
      |> on_server(OtherServer)
      |> run(Metadata, document: :protected_resource)
      |> Flow.json()
      |> Map.fetch!("resource")

    assert resource == "https://other.example.test/mcp"

    registered =
      :post
      |> conn("/", %{"client_name" => "Claude", "redirect_uris" => [Flow.redirect_uri()]})
      |> on_server(OtherServer)
      |> run(Registration, [])

    assert registered.status == 201

    %{"client_id" => client_id} = Flow.json(registered)

    refused =
      :post
      |> conn("/", %{"grant_type" => "password", "client_id" => client_id})
      |> on_server(OtherServer)
      |> run(Token, [])

    assert Flow.json(refused) == %{"error" => "unsupported_grant_type"}

    revoked =
      :post
      |> conn("/", %{"token" => "unknown", "client_id" => client_id})
      |> on_server(OtherServer)
      |> run(Revocation, [])

    assert revoked.status == 200
  end

  test "Bearer authenticates on the connection's server" do
    user = User.admin()

    conn =
      :post
      |> conn("/")
      |> put_req_header("authorization", "Bearer " <> Flow.mint(user).__metadata__.token)
      |> on_server(OtherServer)
      |> run(Bearer, [])

    refute conn.halted
    assert conn.assigns.mcp_access_token.user_id == user.id
  end

  test "a plug's own server: wins over the connection's" do
    own = [server: McpGatehouse.Test.Server, document: :protected_resource]
    conn = :get |> conn("/") |> on_server(OtherServer) |> run(Metadata, own)

    assert Flow.json(conn)["resource"] == "https://mcp.example.test/mcp"

    challenge =
      :post
      |> conn("/")
      |> on_server(OtherServer)
      |> run(Bearer, server: McpGatehouse.Test.Server)
      |> get_resp_header("www-authenticate")

    assert [~s(Bearer resource_metadata="https://mcp.example.test/) <> _path] = challenge
  end

  test "every library plug raises without a server, naming both ways to configure one" do
    for {plug, opts} <- @route_plugs ++ @pipeline_plugs do
      error = assert_raise ArgumentError, fn -> :post |> conn("/", %{}) |> run(plug, opts) end

      assert error.message =~ inspect(plug)
      assert error.message =~ "plug McpGatehouse.Plug.Server, server: MyAppWeb.Mcp"
      assert error.message =~ "pass it `server: MyAppWeb.Mcp`"
    end
  end

  test "an unconfigured Bearer never lets a request through, not even with a valid token" do
    token = Flow.mint(User.admin()).__metadata__.token

    conn = put_req_header(conn(:post, "/"), "authorization", "Bearer " <> token)

    assert_raise ArgumentError, ~r/McpGatehouse.Plug.Bearer has no MCP server/, fn ->
      UnconfiguredMcpPipeline.call(conn, UnconfiguredMcpPipeline.init([]))
    end

    refute_received :reached_past_bearer
  end
end
