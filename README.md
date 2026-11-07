# mcp_gatehouse

OAuth 2.1 and request plumbing for an [MCP](https://modelcontextprotocol.io)
server built with [`ash_ai`](https://github.com/ash-project/ash_ai) on Ash and
Phoenix. `ash_ai` turns your Ash actions into MCP tools; this library puts a
gate in front of them:

- **An OAuth 2.1 authorization server** of its own — RFC 7591 dynamic client
  registration, authorization code + PKCE (S256 only), refresh token rotation
  with replay detection and idle expiry, RFC 7009 revocation, RFC 8414 /
  RFC 9728 discovery, RFC 9207 `iss` on every authorization response.
- **Consent flow helpers** — validate, approve and deny an authorization
  request; your app renders the page.
- **Plugs** around `AshAi.Mcp.Router` — bearer authentication, rate limiting
  keyed on a trusted client address, and PostHog-style `$mcp_*` analytics.
- **A read-only scope policy** — a domain fragment that keeps tokens without
  `mcp:write` away from create, update and destroy actions.
- **A `report_missing_capability` tool** — lets the model record what it could
  not answer, so you know which tool to build next.
- **Tool description helpers** — shared paging and intent wording.

The library owns protocol and security behaviour. Your app owns the tables,
users, consent page, role gate, analytics backend and tools.

This is not an official Ash project.

## When to use it

[`ash_authentication_oauth2_server`](https://hexdocs.pm/ash_authentication_oauth2_server)
is the general-purpose option. Pick mcp_gatehouse when:

- your app is on `ash_authentication` 4.x, or does not use `ash_authentication`
  at all (that library requires 5.x);
- you want **opaque tokens** stored only as SHA-256 hashes, so revoking one
  takes effect on the next request, rather than JWT access tokens that stay
  valid until they expire;
- you want the user re-loaded by your own code on **every request**, so a
  deleted or demoted user loses MCP access immediately;
- you want MCP credentials **siloed**: their own tables and verification path,
  so no other token your app issues authenticates at `/mcp`, and no MCP token
  authenticates anywhere else.

The data model assumes multi-tenancy: every token belongs to a `user_id` and a
`company_id` (both UUIDs), and users are loaded within that tenant. A
single-tenant app can use one fixed tenant id.

## Installation

```elixir
def deps do
  [
    {:mcp_gatehouse, github: "sephianl/mcp_gatehouse", tag: "v0.1.0"},
    {:simple_sat, "~> 0.1"}
  ]
end
```

- The library depends on a fork of `ash_ai`, pinned in its `mix.exs`. Do not
  declare `ash_ai` yourself; if you must, use the identical source and ref, or
  Mix reports diverged dependencies. `import_deps: [:ash_ai]` in your
  `.formatter.exs` resolves transitively.
- Every action on the library's resources is policy-authorized, so Ash needs a
  SAT solver at runtime: `simple_sat` or `picosat_elixir`, without `only:`.
- The library exports no formatter settings; do not add it to `import_deps`.

## Wiring it up

### 1. Resources

Three thin resources over the library's fragments, in a domain of their own:

```elixir
defmodule MyApp.Mcp.OAuth do
  use Ash.Domain

  resources do
    resource MyApp.Mcp.OAuth.Client
    resource MyApp.Mcp.OAuth.AuthorizationCode
    resource MyApp.Mcp.OAuth.AccessToken
  end
end

defmodule MyApp.Mcp.OAuth.Client do
  use Ash.Resource,
    domain: MyApp.Mcp.OAuth,
    data_layer: AshPostgres.DataLayer,
    fragments: [McpGatehouse.OAuth.ClientFragment]

  postgres do
    table "mcp_oauth_clients"
    repo MyApp.Repo
  end
end

defmodule MyApp.Mcp.OAuth.AccessToken do
  use Ash.Resource,
    domain: MyApp.Mcp.OAuth,
    data_layer: AshPostgres.DataLayer,
    fragments: [McpGatehouse.OAuth.AccessTokenFragment]

  postgres do
    table "mcp_oauth_access_tokens"
    # The primary, not a replica: a lagging replica would hide a just-minted token.
    repo MyApp.Repo

    references do
      reference :user, on_delete: :delete
      reference :company, on_delete: :delete
    end
  end

  relationships do
    belongs_to :user, MyApp.Accounts.User, define_attribute?: false, allow_nil?: false
    belongs_to :company, MyApp.Accounts.Company, define_attribute?: false, allow_nil?: false
  end
end
```

`MyApp.Mcp.OAuth.AuthorizationCode` has the same shape over
`McpGatehouse.OAuth.AuthorizationCodeFragment` and
`mcp_oauth_authorization_codes`. Generate the migration with
`mix ash.codegen add_mcp_oauth`.

Every action is authorized for `McpGatehouse.OAuth.ServerActor` only. Client
and authorization code have no primary read; do not load relationships from
them.

### 2. User lookup

A token is read before anyone is authenticated, so its user is loaded as
`McpGatehouse.OAuth.ServerActor`. Grant exactly that lookup on your user
resource, **before** any policy that requires the actor to belong to a tenant:

```elixir
policies do
  bypass McpGatehouse.OAuth.Checks.ServerActor do
    authorize_if action(:get_by_id)
  end

  # ... existing policies
end
```

`ServerActor` is its own struct, not a user with a reserved role, so no stored
account can ever hold it.

### 3. Server module

One module implements `McpGatehouse.Server`; every plug and the consent helpers
reach your app through it.

```elixir
defmodule MyAppWeb.Mcp do
  @behaviour McpGatehouse.Server

  alias McpGatehouse.OAuth.ServerActor
  alias MyApp.Accounts.User

  @impl true
  def otp_app, do: :my_app

  @impl true
  def server_name, do: "My App"

  @impl true
  def endpoint, do: MyAppWeb.Endpoint

  @impl true
  def client_resource, do: MyApp.Mcp.OAuth.Client
  @impl true
  def authorization_code_resource, do: MyApp.Mcp.OAuth.AuthorizationCode
  @impl true
  def access_token_resource, do: MyApp.Mcp.OAuth.AccessToken

  @impl true
  def load_user(user_id, company_id) do
    case User.get_by_id(user_id, actor: ServerActor.new(), tenant: company_id) do
      {:ok, %User{} = user} -> {:ok, user}
      _not_found -> :error
    end
  end

  @impl true
  def consent_identity(%User{role: :admin, id: id, company_id: company_id}),
    do: {:ok, id, company_id}

  def consent_identity(_user), do: :error

  @impl true
  def capture_event(event, distinct_id, company_id, properties),
    do: MyApp.Analytics.capture(event, distinct_id, company_id, properties)
end
```

| callback | what it does |
|---|---|
| `otp_app/0` | Its version is reported as `$mcp_server_version`; its env holds `:filtered_parameters`. |
| `server_name/0` | Reported as `$mcp_server_name`. Must equal the `mcp_name:` literal given to `AshAi.Mcp.Router`. |
| `endpoint/0` | Every advertised URL is built from its `url/0` and `path/1`. |
| `client_resource/0`, `authorization_code_resource/0`, `access_token_resource/0` | Your resources from step 1. |
| `load_user/2` | Loads the actor for a token, on every request and every refresh. Must load within the tenant; return `:error` for a user that no longer exists or may no longer sign in. |
| `consent_identity/1` | Who a signed-in user approves access as: `{:ok, user_id, company_id}`, or `:error` to refuse (fails closed with `access_denied`). |
| `capture_event/4` | Sends one analytics event; must return `:ok`. A crash is logged, not passed on to the response. |

Optional callbacks:

| callback | default |
|---|---|
| `context/1` | `%{}` — extra Ash context for an authenticated request; `mcp_scopes` takes precedence over a key of that name |
| `filtered_parameters/0` | `config :my_app, :filtered_parameters` when a list, else `~w(password token secret code_verifier code_challenge)` — redacted from analytics by substring |
| `analytics_payloads/0` | `:input` — `:envelope` (no arguments), `:input` (arguments and error messages) or `:full` (adds responses) |
| `trusted_proxies/0` | `[]` — addresses or CIDR ranges trusted to append to `X-Forwarded-For` |
| `refresh_idle_ttl/0` | 90 days, in seconds — how long a refresh token may sit unused |

### 4. Router

The paths are fixed: `/mcp`, `/mcp/oauth/{authorize,token,register,revoke}`
and `/.well-known/oauth-{protected-resource,authorization-server}`, relative to
the endpoint. The discovery documents advertise exactly these, so mount every
route exactly there.

```elixir
pipeline :mcp_oauth do
  plug McpGatehouse.Plug.Server, server: MyAppWeb.Mcp
  plug :accepts, ["json"]
  plug McpGatehouse.Plug.RateLimit, prefix: "mcp_oauth", limit: 60
end

pipeline :mcp_consent do
  plug MyAppWeb.Plugs.McpConsentRole
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

# After the /mcp/oauth scopes, or the forward captures them.
scope "/mcp" do
  pipe_through :mcp

  forward "/", AshAi.Mcp.Router,
    tools: @mcp_tools,
    otp_app: :my_app,
    mcp_name: "My App"
end
```

- **Name the server on the pipeline, not on routes.** `McpGatehouse.Plug.Server`
  puts it on the connection for the plugs after it. Phoenix compiles route plug
  options into the router, so `server:` on a route would make the router depend
  on your endpoint and resources at compile time (an xref cycle).
- **Route plugs need the `[]` third argument.** Phoenix's route macros require
  it, unlike `Plug.Router`.
- **Ordering:** the `/mcp/oauth` scopes come before the `/mcp` forward.
- **Literals only:** write `mcp_name:` as a literal; router options are
  evaluated at compile time.
- **Rate limits:** the `:ip` key trusts `X-Forwarded-For` only as far as
  `trusted_proxies/0` allows (see `McpGatehouse.ClientIp`). For a per-user
  budget, add a second `RateLimit` with `key: :actor` after `Bearer`.
- **Analytics:** `Bearer` assigns the token as `:mcp_access_token` and sets the
  Ash actor and tenant; plugs that set analytics context go between `Bearer`
  and `Analytics`.
- **Body parsing:** the endpoint must parse urlencoded and JSON bodies.

### 5. Consent controller

You render the page; `McpGatehouse.OAuth.Authorization` does the rest.

```elixir
defmodule MyAppWeb.Mcp.OAuthAuthorizeController do
  use MyAppWeb, :controller

  alias McpGatehouse.OAuth.Authorization

  plug McpGatehouse.Plug.NoStore

  def show(conn, params) do
    case Authorization.validate(MyAppWeb.Mcp, params) do
      {:ok, authorization} ->
        conn
        |> Authorization.permit_form_redirect(authorization)
        |> render(:consent, authorization: authorization)

      {:error, error} ->
        conn |> put_status(:bad_request) |> json(error)
    end
  end

  def create(conn, %{"decision" => "deny"} = params) do
    case Authorization.deny(MyAppWeb.Mcp, params) do
      {:ok, callback} -> redirect(conn, external: callback)
      {:error, error} -> conn |> put_status(:bad_request) |> json(error)
    end
  end

  def create(conn, params) do
    with {:ok, authorization} <- Authorization.validate(MyAppWeb.Mcp, params),
         {:ok, callback} <-
           Authorization.approve(MyAppWeb.Mcp, authorization, conn.assigns.current_user) do
      redirect(conn, external: callback)
    else
      {:error, error} -> conn |> put_status(:bad_request) |> json(error)
    end
  end
end
```

The form posts back `client_id`, `redirect_uri`, `code_challenge`,
`code_challenge_method=S256`, `state`, `scope` and `response_type=code`, plus
`decision=deny` on the deny button. Describe each of `authorization.scopes` in
your own (translated) words.

The authorize routes **must** sit behind session authentication, CSRF
protection and a role gate that decides by the same rule as
`consent_identity/1`, on both GET and POST. The library cannot enforce these.

A signed-out user hitting `GET /mcp/oauth/authorize` must be sent to sign-in
and brought back to the full original URL, query string intact, or the MCP
client waits for a callback that never comes. One way: on a signed-out GET,
store `request_path <> "?" <> query_string` in the session and redirect there
after sign-in — only if it is a local path (`/` followed by neither `/` nor
`\`), so it can never send a signed-in user off-site.

### 6. Tools and config

```elixir
config :my_app,
  ash_domains: [..., MyApp.Mcp.OAuth, McpGatehouse.Tools],
  filtered_parameters: ~w(password token secret code_verifier code_challenge)

config :phoenix, :filter_parameters, ~w(password token secret code_verifier code_challenge)
```

Leave `code` out of the filter lists: the match is by substring and would
redact `barcode` and `postcode`.

`McpGatehouse.Tools` serves `report_missing_capability`; add it to the router's
`tools:` list. Every domain that carries tools gets the read-only policy, and
every tool the `context` argument:

```elixir
use Ash.Domain,
  extensions: [AshAi],
  fragments: [McpGatehouse.ReadOnlyScopePolicy]

tools do
  tool :list_orders, MyApp.Order, :list do
    description """
    Lists orders.

    #{McpGatehouse.ToolDocs.paging()}
    """

    argument :context, Ash.Type.String, description: McpGatehouse.Intent.description()
  end
end
```

The policy only reaches resources whose own `authorizers` include
`Ash.Policy.Authorizer`; Ash warns at compile time for every resource that
lacks it. Give each such resource policies scoped to the action types it serves
(see `McpGatehouse.ReadOnlyScopePolicy`). Paginated tool actions should cap at
`McpGatehouse.ToolDocs.page_cap()`.

### 7. Tests

- Point `config :mcp_gatehouse, :rate_limiter` at a stub with Hammer's `hit/3`
  in `config/test.exs`, or the whole suite shares one real bucket per address.
- The library's own suite runs on `Ash.DataLayer.Ets`, which cannot prove
  single use under concurrency. Worth a test on your real data layer: two
  concurrent exchanges of one code yield exactly one 200 and one
  `invalid_grant`.
- Also worth a test each: a consent POST without a CSRF token is rejected, a
  role the gate refuses gets 403 on both GET and POST, and `load_user/2`
  resolves a user in and only in the token's tenant.

## Security notes

- Codes, access tokens and refresh tokens are random, returned once, and stored
  only as SHA-256 hashes.
- Access tokens are opaque and checked against the database on every request,
  together with `load_user/2`, so revocation and user removal take effect
  immediately.
- PKCE is mandatory, S256 only. A `response_type` other than `code` is refused.
- Refresh tokens rotate. A revoked refresh token presented again by its own
  client more than 5 seconds after revocation revokes the whole grant (every
  token for that client, user and tenant). A refresh token unused for
  `refresh_idle_ttl/0` stops rotating.
- Registration refuses redirect URIs with a fragment, userinfo, a backslash or
  a host that is not plain hostname characters, more than 10 of them, any
  longer than 2,000 characters, and a `client_name` over 200 characters.
- `Bearer` rejects a token whose user loads into another tenant, and adds
  `error="invalid_token"` to the challenge when a token was presented.
- The tenant a token reaches is fixed by the human who consented
  (`consent_identity/1`), never by anything the client sent.
- Only `mcp:read` is granted today; the read-only policy enforces it on your
  domains.

## Limitations

- RFC 8707 `resource` indicators are accepted and ignored. Tokens are bound to
  their audience implicitly: only the deployment that issued them accepts them.
- No Client ID Metadata Documents (CIMD); clients register dynamically.
- No absolute refresh lifetime: a grant lives as long as it keeps refreshing.
- No purge job for expired codes and revoked or idle tokens. If you write one,
  keep rotated rows at least `refresh_idle_ttl/0`, or replay detection weakens.
- No screen for users to list and revoke their grants.

## Development

```sh
mix deps.get
mix format --check-formatted
MIX_ENV=test mix compile --warnings-as-errors
mix test --warnings-as-errors
mix credo
mix dialyzer
```

## License

MIT — see [LICENSE](LICENSE).
