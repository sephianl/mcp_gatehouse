defmodule McpGatehouse.Test.RateLimiterStub do
  @moduledoc """
  Stands in for the Hammer counter in tests, configured as `config
  :mcp_gatehouse, :rate_limiter`.

  Reports each hit to the calling process — under `Plug.Test` the plug runs in
  the test process — and denies every key under the `denied` prefix, so a test
  picks the outcome by picking a prefix instead of mutating app env.
  """

  @spec hit(String.t(), pos_integer(), pos_integer()) :: {:allow, 1} | {:deny, pos_integer()}
  def hit(key, window_ms, limit) do
    send(self(), {:rate_limit_hit, key, window_ms, limit})

    if String.starts_with?(key, "denied:"), do: {:deny, window_ms}, else: {:allow, 1}
  end
end
