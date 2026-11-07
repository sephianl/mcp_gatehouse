defmodule McpGatehouse do
  @moduledoc """
  OAuth 2.1 and request plumbing for an MCP server built with `ash_ai` on Ash and
  Phoenix: a siloed OAuth 2.1 authorization server (dynamic client registration,
  authorization code + PKCE, refresh rotation, revocation) and the plugs around
  `ash_ai`'s `AshAi.Mcp.Router` — bearer authentication, rate limiting and
  PostHog MCP analytics.

  The authorization server is deliberately its own: separate tables, separate
  token values, separate verification path. A credential issued by any other
  OAuth server the host runs cannot authenticate here and the other way round,
  because a partner token usually carries its owner's whole role while an MCP
  token is handed to a model and has to be scoped accordingly.

  ## What the host provides

  1. **Resources.** An Ash domain with three resources built from
     `McpGatehouse.OAuth.ClientFragment`, `McpGatehouse.OAuth.AuthorizationCodeFragment`
     and `McpGatehouse.OAuth.AccessTokenFragment`. The host chooses the data layer,
     table names (conventionally `mcp_oauth_clients`, `mcp_oauth_authorization_codes`,
     `mcp_oauth_access_tokens`), repo (pin the primary: a lagging replica would hide
     a just-issued code or token) and any foreign keys on `user_id`/`company_id`
     (`belongs_to ..., define_attribute?: false, allow_nil?: false`). Every action
     on them is policy-authorized, so the host needs a SAT solver at runtime:
     `picosat_elixir` or `simple_sat`.

  2. **A server module** implementing `McpGatehouse.Server`: where the resources
     and endpoint are, how a token's user is loaded (within its tenant), who may
     consent, and where analytics go. The host's user resource grants the lookup
     to `McpGatehouse.OAuth.ServerActor`:

         bypass McpGatehouse.OAuth.Checks.ServerActor do
           authorize_if action(:get_by_id)
         end

     placed before any policy that requires the actor to belong to a company.

  3. **Routes.** The paths are fixed: the library serves and advertises `/mcp`,
     `/mcp/oauth/{authorize,token,register,revoke}` and
     `/.well-known/oauth-{protected-resource,authorization-server}`, built from
     the endpoint's `url/0` and `path/1`, and nothing configures them. Mount each
     route exactly there; mounted elsewhere, the discovery documents point at
     404s and nothing reports it. The `/mcp/oauth` scopes must come before the
     `/mcp` forward, or the forward captures them:

         pipeline :mcp_oauth do
           plug McpGatehouse.Plug.Server, server: MyAppWeb.Mcp
           plug :accepts, ["json"]
           plug McpGatehouse.Plug.RateLimit, prefix: "mcp_oauth", limit: 60
         end

         pipeline :mcp do
           plug McpGatehouse.Plug.Server, server: MyAppWeb.Mcp
           plug :accepts, ["json"]
           plug McpGatehouse.Plug.RateLimit, prefix: "mcp", limit: 600
           plug McpGatehouse.Plug.Bearer
           plug McpGatehouse.Plug.Analytics
         end

         scope "/.well-known" do
           pipe_through :mcp_oauth
           get "/oauth-protected-resource", McpGatehouse.Plug.Metadata, document: :protected_resource
           get "/oauth-authorization-server", McpGatehouse.Plug.Metadata, document: :authorization_server
         end

         scope "/mcp/oauth" do
           pipe_through :mcp_oauth
           post "/register", McpGatehouse.Plug.Registration, []
           post "/token", McpGatehouse.Plug.Token, []
           post "/revoke", McpGatehouse.Plug.Revocation, []
         end

         scope "/mcp/oauth", MyAppWeb.Mcp do
           pipe_through [:browser, :browser_auth, :mcp_consent]
           get "/authorize", OAuthAuthorizeController, :show
           post "/authorize", OAuthAuthorizeController, :create
         end

         scope "/mcp" do
           pipe_through :mcp
           forward "/", AshAi.Mcp.Router, tools: @mcp_tools, otp_app: :my_app, mcp_name: "My App"
         end

     The authorize routes must sit behind the host's session authentication, CSRF
     protection and a role gate that decides by the same rule as
     `c:McpGatehouse.Server.consent_identity/1`. The library cannot enforce any of
     the three; `McpGatehouse.OAuth.Authorization.approve/3` only fails closed when
     `consent_identity/1` refuses. The consent controller uses
     `McpGatehouse.OAuth.Authorization` and `plug McpGatehouse.Plug.NoStore`.

     The session authentication on `GET /mcp/oauth/authorize` must send a
     signed-out user to sign-in and back to the full original URL, query string
     intact, or the MCP client waits for a callback that never comes. Remember
     GET targets only and return only to a local path; the README's consent
     section describes one way to do it.

     The server module is named once per pipeline, by `McpGatehouse.Plug.Server`,
     and the route plugs take no `server:`: Phoenix escapes route plug options
     into the router at compile time, so naming it on a route makes the router
     depend on the server module at compile time — and, through it, on the
     endpoint and resources it reaches — which `mix xref` reports as
     compile-connected cycles and which recompiles the router whenever any of
     them changes. Under `plug_init_mode: :runtime` (dev and test) a pipeline
     plug's options are only a runtime reference; the pipeline plugs after it
     omit `server:` too. A plug's own `server:`
     still wins over the connection's; a plug with neither raises per request.

     Write `mcp_name:` as a literal equal to `c:McpGatehouse.Server.server_name/0`:
     router options are evaluated when the router compiles. For the same reason
     the plugs read nothing from the server module in `init/1`.

  4. **Config.** Add the OAuth domain and `McpGatehouse.Tools` (which serves
     `report_missing_capability`) to `config :my_app, ash_domains`, and every
     domain that carries tools gets the `McpGatehouse.ReadOnlyScopePolicy`
     fragment. Every resource of those domains then needs `Ash.Policy.Authorizer`
     in its own `authorizers`, with policies scoped to its action types: Ash
     warns at compile time for each one without it, and the fragment does
     nothing for it (see `McpGatehouse.ReadOnlyScopePolicy`). Keep a
     `config :my_app, :filtered_parameters` list (without `code`, which would
     redact `barcode` and `postcode`) for analytics redaction, and use the same
     list for Phoenix's `:filter_parameters`.

  5. **Tests.** Point `config :mcp_gatehouse, :rate_limiter` at a stub with
     Hammer's `hit/3` in the test environment, or the suite shares one real
     60-per-minute bucket per address.

  ## Audience binding

  RFC 8707 `resource` indicators are accepted and ignored. Tokens are bound to
  their audience implicitly: they are opaque rows in this deployment's tables and
  only this deployment's `/mcp` accepts them, so a token issued by one host never
  authenticates at another.

  ## Deferred

    * An absolute refresh lifetime (time since the original consent): it needs a
      column recording that consent. Refresh tokens do expire after
      `c:McpGatehouse.Server.refresh_idle_ttl/0` unused.
    * A purge job for expired codes and revoked or idle token rows. Replay
      detection needs rotated rows for as long as the idle TTL, so a purge must
      not delete them any sooner.
    * A screen where users or administrators list and revoke their grants.
  """
end
