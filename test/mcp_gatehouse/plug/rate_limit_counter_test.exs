defmodule McpGatehouse.Plug.RateLimitCounterTest do
  @moduledoc """
  Without a configured stub the plug counts with `McpGatehouse.RateLimiter`,
  which the library's application starts. Not async: it removes the test stub
  from app env for its duration.

  The plug is initialised while the stub is still configured, so a plug that
  read the counter in `init/1` instead of per request would keep counting with
  the stub and never deny.
  """
  use ExUnit.Case, async: false

  import Plug.Test

  alias McpGatehouse.Plug.RateLimit
  alias McpGatehouse.Test.Server

  setup do
    opts =
      RateLimit.init(
        prefix: "counter-#{System.unique_integer([:positive])}",
        limit: 2,
        server: Server
      )

    stub = Application.fetch_env!(:mcp_gatehouse, :rate_limiter)
    Application.delete_env(:mcp_gatehouse, :rate_limiter)
    on_exit(fn -> Application.put_env(:mcp_gatehouse, :rate_limiter, stub) end)

    %{opts: opts}
  end

  test "the library's own counter allows up to the limit and then denies", %{opts: opts} do
    statuses =
      for _request <- 1..3, do: :get |> conn("/") |> RateLimit.call(opts) |> Map.get(:status)

    assert statuses == [nil, nil, 429]
  end
end
