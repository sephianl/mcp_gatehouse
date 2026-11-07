defmodule McpGatehouse.Application do
  @moduledoc """
  Starts the library's own rate-limit counter, `McpGatehouse.RateLimiter`, so a
  host that mounts `McpGatehouse.Plug.RateLimit` has nothing to supervise itself.

  It always starts, also when `config :mcp_gatehouse, :rate_limiter` names the
  host's own counter: the plug reads that setting per request, so the library's
  counter is there to fall back to and otherwise sits idle.
  """
  use Application

  @impl Application
  @spec start(Application.start_type(), term()) :: Supervisor.on_start()
  def start(_type, _args) do
    children = [{McpGatehouse.RateLimiter, clean_period: to_timeout(minute: 10)}]

    Supervisor.start_link(children, strategy: :one_for_one, name: McpGatehouse.Supervisor)
  end
end
