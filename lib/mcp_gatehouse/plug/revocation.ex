defmodule McpGatehouse.Plug.Revocation do
  @moduledoc """
  RFC 7009 token revocation.

      post "/mcp/oauth/revoke", McpGatehouse.Plug.Revocation, []

  in a scope piped through a pipeline that starts with `McpGatehouse.Plug.Server`.

  Answers 200 whatever happens, including for a token that never existed — the
  spec requires it, and it keeps the endpoint from telling an attacker which of
  their guesses are real tokens. The presented value is looked up as an access
  token first, then as a refresh token.

  The presented `client_id` has to be the one the token was issued to (RFC 7009
  §2.1). Clients here are public and hold no secret, so this is not proof of
  identity; it stops one registered client revoking another's grants by
  presenting a token it happened to observe.

  The response is marked `no-store`.
  """
  @behaviour Plug

  import Plug.Conn

  alias McpGatehouse.OAuth.Lookup
  alias McpGatehouse.OAuth.ServerActor
  alias McpGatehouse.Plug.NoStore
  alias McpGatehouse.Plug.Options

  @impl Plug
  @spec init(keyword()) :: map()
  def init(opts), do: Options.validate(__MODULE__, opts)

  @impl Plug
  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, opts) do
    server = Options.server(conn, __MODULE__, opts)
    conn = NoStore.call(conn, [])

    revoke(server, conn.params)

    send_resp(conn, 200, "")
  end

  defp revoke(server, %{"token" => token, "client_id" => client_id}) when is_binary(client_id) do
    case find(server, token) do
      {:ok, %{client_id: ^client_id} = found} ->
        server.access_token_resource().revoke(found, actor: ServerActor.new())

      _mismatched_or_missing ->
        :ok
    end
  end

  defp revoke(_server, _params), do: :ok

  defp find(server, token) do
    case Lookup.fetch_by_token(server, token) do
      {:ok, found} -> {:ok, found}
      :error -> Lookup.fetch_by_refresh_token(server, token)
    end
  end
end
