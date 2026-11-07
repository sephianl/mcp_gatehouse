defmodule McpGatehouse.ClientIp do
  @moduledoc """
  The address a request came from, safe to key a rate limit on.

  `conn.remote_ip` is the nearest hop — the host's ingress in production — so
  keying on it alone collapses every caller into one bucket. `X-Forwarded-For`
  carries the chain, but each proxy appends the address it received the request
  from, so the entries a caller wrote sit to the LEFT of the one our own ingress
  vouched for. Reading the left-most entry lets a caller mint a fresh bucket per
  request by forging the header, which defeats the limit entirely.

  So the client is resolved by trust, not by position: `RemoteIp` walks the chain
  from the right and returns the first address that is not a trusted proxy. The
  trusted set is the reserved/private ranges (which `RemoteIp` always skips) plus
  whatever the host lists in `c:McpGatehouse.Server.trusted_proxies/0`, such as
  its load balancer's ranges. Getting that set slightly wrong only ever
  over-collapses buckets — the walk can never reach a caller-forged entry,
  because our ingress appended the real address to its right.

  That premise holds for `X-Forwarded-For` alone, so it is the only header read.
  `Forwarded`, `X-Client-Ip` and `X-Real-Ip` are passed through untouched by
  common ingresses; a caller that sends one after its own `X-Forwarded-For`
  would otherwise choose its own bucket. The host's ingress must therefore
  append to `X-Forwarded-For`; without one, every caller falls back to
  `conn.remote_ip`.
  """

  @doc "The client address as a string, from `X-Forwarded-For` by trust, else the socket peer."
  @spec resolve(Plug.Conn.t(), [String.t()]) :: String.t()
  def resolve(conn, trusted_proxies) do
    conn.req_headers
    |> RemoteIp.from(headers: ["x-forwarded-for"], proxies: trusted_proxies)
    |> or_socket(conn)
  end

  defp or_socket(nil, conn), do: conn.remote_ip |> :inet.ntoa() |> to_string()
  defp or_socket(address, _conn), do: address |> :inet.ntoa() |> to_string()
end
