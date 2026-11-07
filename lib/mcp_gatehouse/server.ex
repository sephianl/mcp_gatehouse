defmodule McpGatehouse.Server do
  @moduledoc """
  The host's adapter: the one module through which every library plug and
  `McpGatehouse.OAuth.Authorization` reaches what belongs to the host.

  Every library plug reaches it through `McpGatehouse.Plug.Server` earlier in the
  pipeline (or its own `server:` option), and `McpGatehouse.OAuth.Authorization`
  takes it as its first argument. Name it on the pipeline, not on routes: see
  `McpGatehouse.Plug.Server` for the compile-time dependency a route's
  `server:` creates. The library never decides which users exist, who may
  consent, which tenant a user belongs to, where analytics go or which tables
  hold the OAuth rows — it asks this module.

  Optional callbacks are resolved at call time, never in a plug's `init/1`, so a
  production router that compiles its pipelines does not freeze them into the
  build. See `McpGatehouse.Server.Callbacks` for the defaults.
  """

  @typedoc "The access token row a request authenticated with, as the host resource returns it."
  @type token :: struct()

  @doc "The OTP app whose version is reported as `$mcp_server_version` and whose env holds `:filtered_parameters`."
  @callback otp_app() :: atom()

  @doc """
  The server name reported to analytics as `$mcp_server_name`.

  Pass the same literal as `mcp_name:` to `AshAi.Mcp.Router`, so the name a client
  sees on `initialize` and the name in analytics agree.
  """
  @callback server_name() :: String.t()

  @doc "The Phoenix endpoint (or anything with `url/0` and `path/1`) every advertised URL is built from."
  @callback endpoint() :: module()

  @doc "The host resource built from `McpGatehouse.OAuth.ClientFragment`."
  @callback client_resource() :: Ash.Resource.t()

  @doc "The host resource built from `McpGatehouse.OAuth.AuthorizationCodeFragment`."
  @callback authorization_code_resource() :: Ash.Resource.t()

  @doc "The host resource built from `McpGatehouse.OAuth.AccessTokenFragment`."
  @callback access_token_resource() :: Ash.Resource.t()

  @doc """
  Loads the actor a token or refresh grant acts as.

  It MUST load within the tenant `company_id` (for example with `tenant:
  company_id`), so a user cannot be resolved across companies. The plugs reject
  `{:ok, nil}`, and an actor whose `:company_id` differs from `company_id`.
  Return `:error` for a user that no longer exists or may no longer sign in.
  """
  @callback load_user(user_id :: String.t(), company_id :: String.t()) ::
              {:ok, actor :: term()} | :error

  @doc """
  The identity a signed-in user approves MCP access as.

  Return `:error` when this user may not approve MCP access; the approval then
  fails closed with `access_denied`. The identity is taken from the signed-in
  user only, never from anything the client sent, so the tenant a token reaches
  is fixed by the human who consented.
  """
  @callback consent_identity(user :: term()) ::
              {:ok, user_id :: String.t(), company_id :: String.t()} | :error

  @doc "Sends one analytics event. Called from a `before_send` hook; it must return `:ok`."
  @callback capture_event(
              event :: String.t(),
              distinct_id :: String.t(),
              company_id :: String.t() | nil,
              properties :: map()
            ) :: :ok

  @doc """
  Extra Ash context for an authenticated request, merged into the request's Ash
  context alongside `mcp_scopes`, which takes precedence over a host key of that
  name. Defaults to `%{}`.
  """
  @callback context(token()) :: map()

  @doc """
  Parameter names (matched as substrings, case-insensitively) redacted from
  analytics payloads. Defaults to the host's `config :otp_app, :filtered_parameters`
  when that is a list, else `~w(password token secret code_verifier code_challenge)`.
  """
  @callback filtered_parameters() :: [String.t()]

  @doc """
  How much of a tool call reaches analytics: `:envelope`, `:input` (default) or
  `:full`. See `McpGatehouse.Plug.Analytics`.
  """
  @callback analytics_payloads() :: :envelope | :input | :full

  @doc "Proxy addresses or CIDR ranges trusted to append to `X-Forwarded-For`. Defaults to `[]`."
  @callback trusted_proxies() :: [String.t()]

  @doc "Seconds a refresh token may sit unused before it stops rotating. Defaults to 90 days."
  @callback refresh_idle_ttl() :: pos_integer()

  @optional_callbacks context: 1,
                      filtered_parameters: 0,
                      analytics_payloads: 0,
                      trusted_proxies: 0,
                      refresh_idle_ttl: 0
end
