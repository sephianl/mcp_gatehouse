defmodule McpGatehouse.RateLimiter do
  @moduledoc """
  Hammer counter behind `McpGatehouse.Plug.RateLimit`, separate from any counter
  the host keeps for its other APIs, so a model in an MCP retry loop cannot
  exhaust the budget other integrations authenticate against.

  Counts per node: the ETS backend is not shared across a cluster.
  """
  use Hammer, backend: :ets
end
