defmodule McpGatehouse.Plug.Bearer do
  @moduledoc """
  Authenticates the MCP endpoint against the host's MCP access tokens only.

      plug McpGatehouse.Plug.Bearer

  after `McpGatehouse.Plug.Server` in the pipeline, or with its own
  `server: MyAppWeb.Mcp`. With neither it raises rather than let the request
  through.

  It deliberately has no fallback to any other credential the host accepts: a
  partner OAuth token or an API key usually carries its owner's whole role, and
  accepting one here would hand a model reach nobody scoped for it. The tenant
  comes off the token row, which was stamped from the consenting user.

  A token authenticates while it is neither revoked nor expired and its user
  loads through `c:McpGatehouse.Server.load_user/2` as a non-nil actor whose
  `:company_id`, when it has one, is the token's. The request then carries that
  actor, the token's company as tenant, and an Ash context merged into whatever
  an earlier plug set: the host's `c:McpGatehouse.Server.context/1` plus
  `mcp_scopes`, which `McpGatehouse.ReadOnlyScopePolicy` reads. The token row is
  assigned as `:mcp_access_token` for host plugs. The `Bearer` scheme is matched
  case-insensitively (RFC 7235).

  A rejection is a 401 `{"error":"invalid_token"}` carrying the RFC 9728
  `resource_metadata` challenge, which is how a remote client discovers where to
  authorize, plus `error="invalid_token"` (RFC 6750 §3) when a token was
  presented.
  """
  @behaviour Plug

  import Plug.Conn

  alias Ash.PlugHelpers
  alias McpGatehouse.OAuth.Lookup
  alias McpGatehouse.Plug.Json
  alias McpGatehouse.Plug.Options
  alias McpGatehouse.Server.Callbacks

  @impl Plug
  @spec init(keyword()) :: map()
  def init(opts), do: Options.validate(__MODULE__, opts)

  @impl Plug
  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, opts) do
    server = Options.server(conn, __MODULE__, opts)

    with {:ok, presented} <- bearer_token(conn),
         {:ok, token} <- Lookup.fetch_by_token(server, presented),
         :ok <- usable(token),
         {:ok, actor} <- Callbacks.load_owner(server, token.user_id, token.company_id) do
      authenticated(conn, server, token, actor)
    else
      :missing -> unauthorized(conn, server, :missing)
      _rejected -> unauthorized(conn, server, :invalid)
    end
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      [header | _rest] -> parse_bearer(header)
      [] -> :missing
    end
  end

  defp parse_bearer(header) do
    with [scheme, credential] <- String.split(header, " ", parts: 2),
         "bearer" <- String.downcase(scheme),
         token when token != "" <- String.trim(credential) do
      {:ok, token}
    else
      _not_bearer -> :missing
    end
  end

  defp usable(%{revoked_at: nil, expires_at: expires_at}) do
    if DateTime.after?(expires_at, DateTime.utc_now()), do: :ok, else: :error
  end

  defp usable(_token), do: :error

  defp authenticated(conn, server, token, actor) do
    mcp_context = Map.put(Callbacks.context(server, token), :mcp_scopes, token.scopes)

    conn
    |> PlugHelpers.set_actor(actor)
    |> PlugHelpers.set_tenant(token.company_id)
    |> PlugHelpers.update_context(&Map.merge(&1 || %{}, mcp_context))
    |> assign(:mcp_access_token, token)
  end

  defp unauthorized(conn, server, presented) do
    conn
    |> put_resp_header("www-authenticate", challenge(server, presented))
    |> Json.send_json(401, %{error: "invalid_token"})
    |> halt()
  end

  defp challenge(server, :missing) do
    ~s(Bearer resource_metadata="#{Callbacks.url(server, "/.well-known/oauth-protected-resource")}")
  end

  defp challenge(server, :invalid), do: challenge(server, :missing) <> ~s(, error="invalid_token")
end
