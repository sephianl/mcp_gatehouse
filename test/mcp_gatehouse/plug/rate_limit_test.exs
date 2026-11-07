defmodule McpGatehouse.Plug.RateLimitTest do
  @moduledoc """
  Each surface counts against its own prefix, keyed by the trusted client
  address or by the authenticated actor, and a denied request is a JSON 429.
  The counter is the configured stub here; `RateLimitCounterTest` runs the real
  one.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias Ash.PlugHelpers
  alias McpGatehouse.Plug.RateLimit
  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.Server

  defp limit(conn, opts), do: RateLimit.call(conn, RateLimit.init(Keyword.put_new(opts, :server, Server)))

  test "counts by client address under the surface's prefix" do
    conn = limit(conn(:get, "/"), prefix: "mcp_oauth", limit: 60)

    refute conn.halted
    assert_received {:rate_limit_hit, "mcp_oauth:127.0.0.1", 60_000, 60}
  end

  test "passes the window through" do
    limit(conn(:get, "/"), prefix: "mcp", limit: 5, window_ms: 1_000)

    assert_received {:rate_limit_hit, "mcp:127.0.0.1", 1_000, 5}
  end

  test "keys on the forwarded client behind the server's trusted proxies" do
    :get
    |> conn("/")
    |> put_req_header("x-forwarded-for", "203.0.113.7, 35.191.0.5")
    |> limit(prefix: "mcp", limit: 600)

    assert_received {:rate_limit_hit, "mcp:203.0.113.7", _window, _limit}
  end

  test "keys on the actor when asked to" do
    :get
    |> conn("/")
    |> PlugHelpers.set_actor(%{id: "user-1"})
    |> limit(prefix: "mcp_actor", limit: 120, key: :actor)

    assert_received {:rate_limit_hit, "mcp_actor:actor:user-1", _window, _limit}
  end

  test "falls back to the address when there is no actor to key on" do
    limit(conn(:get, "/"), prefix: "mcp_actor", limit: 120, key: :actor)

    :get
    |> conn("/")
    |> PlugHelpers.set_actor(%{id: nil})
    |> limit(prefix: "mcp_nil", limit: 120, key: :actor)

    assert_received {:rate_limit_hit, "mcp_actor:127.0.0.1", _window, _limit}
    assert_received {:rate_limit_hit, "mcp_nil:127.0.0.1", _window, _limit}
  end

  test "a denied request is a halted JSON 429" do
    conn = limit(conn(:get, "/"), prefix: "denied", limit: 1)

    assert conn.halted
    assert conn.status == 429
    assert Flow.json(conn) == %{"error" => "rate_limited"}
  end

  test "the mounted routes count against their own surfaces" do
    Flow.get("/.well-known/oauth-protected-resource")
    Flow.rpc("tools/list", %{}, nil)

    assert_received {:rate_limit_hit, "mcp_oauth:127.0.0.1", 60_000, 60}
    assert_received {:rate_limit_hit, "mcp:127.0.0.1", 60_000, 600}
  end

  test "init validates its options" do
    assert %{key: :ip, window_ms: 60_000} = RateLimit.init(prefix: "p", limit: 1, server: Server)

    assert_raise ArgumentError, ~r/prefix/, fn -> RateLimit.init(limit: 1, server: Server) end

    assert_raise ArgumentError, ~r/server/, fn ->
      RateLimit.init(prefix: "p", limit: 1, server: "Mcp")
    end

    assert_raise ArgumentError, ~r/key/, fn ->
      RateLimit.init(prefix: "p", limit: 1, server: Server, key: :credential)
    end

    assert_raise ArgumentError, ~r/limit/, fn ->
      RateLimit.init(prefix: "p", limit: 0, server: Server)
    end
  end
end
