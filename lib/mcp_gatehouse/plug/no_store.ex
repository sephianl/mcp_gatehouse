defmodule McpGatehouse.Plug.NoStore do
  @moduledoc """
  Marks a response as uncacheable, for the endpoints that hand out credentials.

  RFC 6749 §5.1 requires it on token responses. The registration response gets
  it for the same reason: it carries the client identity the rest of the flow
  authenticates with. The discovery documents deliberately do not — those are
  meant to be cached.

  The token, registration and revocation plugs apply it themselves; a host adds
  it to its consent controller with `plug McpGatehouse.Plug.NoStore`.
  """
  @behaviour Plug

  import Plug.Conn

  @impl Plug
  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @impl Plug
  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, _opts) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_header("pragma", "no-cache")
  end
end
