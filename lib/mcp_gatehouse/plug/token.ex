defmodule McpGatehouse.Plug.Token do
  @moduledoc """
  The MCP token endpoint: exchanges an authorization code for an opaque access
  token, or rotates a refresh token.

      post "/mcp/oauth/token", McpGatehouse.Plug.Token, []

  in a scope piped through a pipeline that starts with `McpGatehouse.Plug.Server`.

  Clients here are public — they hold no secret — so the PKCE verifier is the
  only proof that the caller is the same party that started the flow. A code is
  redeemed before the token is minted, which is what makes replay useless. A
  replayed code is a plain `invalid_grant` and revokes nothing: it is checked
  before the verifier, and a spent code alone must not be able to cancel
  anyone's grant.

  A refresh rotates: the presented row is revoked and a new one minted, so each
  refresh token works once. On top of that:

    * A revoked refresh token presented again by the client it was issued to
      revokes every live token of its grant (RFC 9700 §4.14.2) — one of the two
      parties holding it is not the client. A presentation within five seconds of
      the revocation is treated as the client's own concurrent retry and only
      refused.
    * A refresh token unused for longer than
      `c:McpGatehouse.Server.refresh_idle_ttl/0` no longer rotates.
    * The user behind the grant has to load again through
      `c:McpGatehouse.Server.load_user/2`, so a removed user's grant stops
      rotating instead of minting tokens nobody can use.

  A grant is every token row sharing a `client_id`, `user_id` and `company_id`,
  not one consent. The replay rule therefore applies to a refresh token however
  it was revoked — rotated, revoked through `McpGatehouse.Plug.Revocation`, or
  revoked with its grant — and it also revokes the tokens of a later, separate
  consent the same user gave under the same client registration.

  A client that loses a refresh response and retries after the grace period is
  signed out by the replay rule; that is the RFC's accepted trade-off. There is
  no absolute grant lifetime: it would need a column recording the original
  consent.

  The raw tokens exist only in the response built here; the rows behind them
  hold nothing but hashes. Losing a redeem or rotate race is an `invalid_grant`;
  any other failure is a 500 `server_error`, logged at error level when it left
  a replayed grant unrevoked. The response is marked `no-store`. The host's
  endpoint must parse urlencoded and JSON bodies.
  """
  @behaviour Plug

  alias McpGatehouse.OAuth.Lookup
  alias McpGatehouse.OAuth.ServerActor
  alias McpGatehouse.Plug.Json
  alias McpGatehouse.Plug.NoStore
  alias McpGatehouse.Plug.Options
  alias McpGatehouse.Server.Callbacks

  require Logger

  @access_token_ttl_s 3600
  @replay_grace_ms 5_000
  @invalid_grant %{
    error: "invalid_grant",
    error_description: "the authorization code or verifier is invalid"
  }

  @impl Plug
  @spec init(keyword()) :: map()
  def init(opts), do: Options.validate(__MODULE__, opts)

  @impl Plug
  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, opts) do
    server = Options.server(conn, __MODULE__, opts)

    conn
    |> NoStore.call([])
    |> grant(server, conn.params)
  end

  defp grant(conn, server, %{"grant_type" => "authorization_code"} = params) do
    with {:ok, code} <- Lookup.fetch_code(server, params["code"]),
         :ok <- unredeemed(code),
         :ok <- unexpired(code),
         :ok <- matching_client(code, params["client_id"]),
         :ok <- matching_redirect(code, params["redirect_uri"]),
         :ok <- verifier_matches(code, params["code_verifier"]),
         {:ok, _redeemed} <- spend(server, code),
         {:ok, token} <- mint_for(server, code) do
      issued(conn, token)
    else
      :error -> failed(conn, @invalid_grant)
      {:error, error} -> failed(conn, error)
    end
  end

  defp grant(conn, server, %{"grant_type" => "refresh_token"} = params) do
    with {:ok, previous} <- Lookup.fetch_by_refresh_token(server, params["refresh_token"]),
         :ok <- issued_to(previous, params["client_id"]),
         :ok <- not_replayed(server, previous),
         :ok <- recently_used(server, previous),
         :ok <- owner_still_loads(server, previous),
         {:ok, _rotated} <- rotate(server, previous),
         {:ok, token} <- mint_for(server, previous) do
      issued(conn, token)
    else
      :error -> failed(conn, @invalid_grant)
      {:error, error} -> failed(conn, error)
    end
  end

  defp grant(conn, _server, _params), do: Json.send_json(conn, 400, %{error: "unsupported_grant_type"})

  defp issued(conn, %{__metadata__: %{token: token, refresh_token: refresh_token}} = minted) do
    Json.send_json(conn, 200, %{
      access_token: token,
      refresh_token: refresh_token,
      token_type: "Bearer",
      expires_in: @access_token_ttl_s,
      scope: Enum.join(minted.scopes, " ")
    })
  end

  defp unredeemed(%{redeemed_at: nil}), do: :ok
  defp unredeemed(_code), do: invalid_grant()

  defp unexpired(%{expires_at: expires_at}) do
    if DateTime.after?(expires_at, DateTime.utc_now()), do: :ok, else: invalid_grant()
  end

  defp matching_client(%{client_id: client_id}, client_id), do: :ok
  defp matching_client(_code, _client_id), do: invalid_grant()

  defp matching_redirect(%{redirect_uri: redirect_uri}, redirect_uri), do: :ok
  defp matching_redirect(_code, _redirect_uri), do: invalid_grant()

  defp verifier_matches(%{code_challenge: challenge}, verifier) when is_binary(verifier) do
    computed = :sha256 |> :crypto.hash(verifier) |> Base.url_encode64(padding: false)

    if Plug.Crypto.secure_compare(computed, challenge), do: :ok, else: invalid_grant()
  end

  defp verifier_matches(_code, _verifier), do: invalid_grant()

  defp issued_to(%{client_id: client_id}, client_id), do: :ok
  defp issued_to(_token, _client_id), do: invalid_grant()

  defp not_replayed(_server, %{revoked_at: nil}), do: :ok

  defp not_replayed(server, %{revoked_at: revoked_at} = previous) do
    if DateTime.diff(DateTime.utc_now(), revoked_at, :millisecond) < @replay_grace_ms,
      do: invalid_grant(),
      else: revoke_grant(server, previous)
  end

  defp revoke_grant(server, %{client_id: client_id, user_id: user_id, company_id: company_id}) do
    tokens = server.access_token_resource()
    grant = "client #{client_id}, user #{user_id}, company #{company_id}"

    with {:ok, live} <-
           tokens.live_in_grant(client_id, user_id, company_id, actor: ServerActor.new()),
         :ok <- revoke_all(tokens, live) do
      Logger.warning(
        "revoked MCP refresh token presented again; revoked #{length(live)} live token(s) of the grant for #{grant}"
      )

      invalid_grant()
    else
      {:error, error} ->
        Logger.error(
          "revoked MCP refresh token presented again, but the grant for #{grant} could not be revoked: " <>
            Exception.format_banner(:error, error)
        )

        {:error, error}
    end
  end

  defp revoke_all(tokens, live) do
    live
    |> Enum.map(&revoke_live(tokens, &1))
    |> Enum.find(:ok, &(&1 != :ok))
  end

  defp revoke_live(tokens, token) do
    case tokens.revoke(token, actor: ServerActor.new()) do
      {:ok, _revoked} -> :ok
      {:error, error} -> already_revoked(error)
    end
  end

  defp already_revoked(%Ash.Error.Invalid{errors: [_stale | _more] = errors} = error) do
    if Enum.all?(errors, &match?(%Ash.Error.Changes.StaleRecord{}, &1)),
      do: :ok,
      else: {:error, error}
  end

  defp already_revoked(error), do: {:error, error}

  defp recently_used(server, %{created_at: created_at}) do
    if DateTime.diff(DateTime.utc_now(), created_at, :second) > Callbacks.refresh_idle_ttl(server),
      do: invalid_grant(),
      else: :ok
  end

  defp owner_still_loads(server, %{user_id: user_id, company_id: company_id}) do
    case Callbacks.load_owner(server, user_id, company_id) do
      {:ok, _actor} -> :ok
      :error -> invalid_grant()
    end
  end

  defp mint_for(server, %{client_id: client_id, user_id: user_id, company_id: company_id, scopes: scopes}) do
    server.access_token_resource().mint(
      %{
        client_id: client_id,
        user_id: user_id,
        company_id: company_id,
        scopes: scopes,
        expires_in: @access_token_ttl_s
      },
      actor: ServerActor.new()
    )
  end

  defp spend(server, code) do
    case server.authorization_code_resource().redeem(code, actor: ServerActor.new()) do
      {:ok, redeemed} -> {:ok, redeemed}
      {:error, _lost_the_race} -> invalid_grant()
    end
  end

  defp rotate(server, previous) do
    case server.access_token_resource().revoke(previous, actor: ServerActor.new()) do
      {:ok, rotated} -> {:ok, rotated}
      {:error, _lost_the_race} -> invalid_grant()
    end
  end

  defp failed(conn, %{error: protocol_error} = oauth_error) when is_binary(protocol_error),
    do: Json.send_json(conn, 400, oauth_error)

  defp failed(conn, _unexpected), do: Json.send_json(conn, 500, %{error: "server_error"})

  defp invalid_grant, do: {:error, @invalid_grant}
end
