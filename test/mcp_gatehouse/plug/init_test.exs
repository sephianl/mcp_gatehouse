defmodule McpGatehouse.Plug.InitTest do
  @moduledoc """
  A production router compiles its pipeline plugs, running `init/1` once at
  build time. So `init/1` must only check literal options: it must not call the
  server module, which need not even be compiled yet.

  For a module that is not loaded, an optional callback silently resolves to its
  default instead of raising, so the unloaded module alone cannot show that
  `init/1` leaves the optional callbacks alone; a loaded probe server that
  reports every call can.
  """
  use ExUnit.Case, async: true

  alias McpGatehouse.Plug.Analytics
  alias McpGatehouse.Plug.Bearer
  alias McpGatehouse.Plug.Metadata
  alias McpGatehouse.Plug.NoStore
  alias McpGatehouse.Plug.RateLimit
  alias McpGatehouse.Plug.Registration
  alias McpGatehouse.Plug.Revocation
  alias McpGatehouse.Plug.Server
  alias McpGatehouse.Plug.Token

  @not_compiled McpGatehouse.Test.NotCompiledYet

  defmodule ProbeServer do
    @moduledoc "A loaded host server that reports every callback the library makes to the calling process."
    @behaviour McpGatehouse.Server

    @impl true
    def otp_app, do: called(:otp_app, :mcp_gatehouse)
    @impl true
    def server_name, do: called(:server_name, "probe")
    @impl true
    def endpoint, do: called(:endpoint, McpGatehouse.Test.Endpoint)
    @impl true
    def client_resource, do: called(:client_resource, McpGatehouse.Test.Client)
    @impl true
    def authorization_code_resource, do: called(:authorization_code_resource, McpGatehouse.Test.AuthorizationCode)

    @impl true
    def access_token_resource, do: called(:access_token_resource, McpGatehouse.Test.AccessToken)
    @impl true
    def load_user(_user_id, _company_id), do: called(:load_user, :error)
    @impl true
    def consent_identity(_user), do: called(:consent_identity, :error)
    @impl true
    def capture_event(_event, _distinct_id, _company_id, _properties), do: called(:capture_event, :ok)

    @impl true
    def context(_token), do: called(:context, %{})
    @impl true
    def filtered_parameters, do: called(:filtered_parameters, [])
    @impl true
    def analytics_payloads, do: called(:analytics_payloads, :full)
    @impl true
    def trusted_proxies, do: called(:trusted_proxies, [])
    @impl true
    def refresh_idle_ttl, do: called(:refresh_idle_ttl, 1)

    defp called(name, value) do
      send(self(), {:server_called, name})
      value
    end
  end

  test "init never touches the server module" do
    for plug <- [Analytics, Bearer, Registration, Revocation, Token, Server] do
      assert %{server: @not_compiled} = plug.init(server: @not_compiled)
    end

    assert %{server: @not_compiled} =
             Metadata.init(server: @not_compiled, document: :protected_resource)

    assert %{server: @not_compiled} =
             RateLimit.init(server: @not_compiled, prefix: "mcp", limit: 1)

    refute Code.ensure_loaded?(@not_compiled)
  end

  test "init calls no callback of a loaded server, optional ones included" do
    assert Code.ensure_loaded?(ProbeServer)

    for plug <- [Analytics, Bearer, Registration, Revocation, Token, Server] do
      plug.init(server: ProbeServer)
    end

    Metadata.init(server: ProbeServer, document: :protected_resource)
    Metadata.init(server: ProbeServer, document: :authorization_server)
    RateLimit.init(server: ProbeServer, prefix: "mcp", limit: 1)
    RateLimit.init(server: ProbeServer, prefix: "mcp", limit: 1, key: :actor)

    refute_received {:server_called, _callback}
  end

  test "without server: init leaves the server to the connection" do
    for plug <- [Analytics, Bearer, Registration, Revocation, Token] do
      refute Map.has_key?(plug.init([]), :server)
    end

    refute Map.has_key?(Metadata.init(document: :protected_resource), :server)
    refute Map.has_key?(RateLimit.init(prefix: "mcp", limit: 1), :server)
  end

  test "init refuses a server: that is not a module" do
    for plug <- [Analytics, Bearer, Registration, Revocation, Token, Server] do
      assert_raise ArgumentError, ~r/#{inspect(plug)}.*server/, fn -> plug.init(server: nil) end
    end
  end

  test "NoStore marks a response uncacheable" do
    conn = :get |> Plug.Test.conn("/") |> NoStore.call(NoStore.init([]))

    assert Plug.Conn.get_resp_header(conn, "cache-control") == ["no-store"]
    assert Plug.Conn.get_resp_header(conn, "pragma") == ["no-cache"]
  end
end
