defmodule McpGatehouse.OAuth.Authorization do
  @moduledoc """
  The authorization endpoint's logic, for the host's consent controller: turns
  a signed-in human into an authorization code for a registered MCP client.

  The host keeps the markup, the session and the role gate; this module keeps
  the checks and the redirects:

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

  The tenant is taken from the approving human by
  `c:McpGatehouse.Server.consent_identity/1` and carried on the code, so the
  company a token can reach is decided by who consented and never by anything
  the client sends. A user that callback refuses is sent back with
  `access_denied`.

  `validate/2` checks, in order: the client is registered, the redirect URI is
  one it registered exactly, `response_type` is absent or `code`, an S256 PKCE
  challenge is present, and `state` and `scope` are absent or strings. A list or
  map in either is an `invalid_request`, not a crash.

  The redirect URI must also pass `McpGatehouse.OAuth.RedirectUri.parse/1`, here
  and in `deny/2`, even when the client registered it. `redirect_host`, the host
  the consent page shows, comes from that parse, and a URI a browser reads
  differently (a backslash before `@`, userinfo, an encoded host) would show one
  host while the callback goes to another. This also refuses such a URI held by
  a client registered before registration applied the same parse.

  Every callback carries the RFC 9207 `iss` parameter, so a client talking to
  several authorization servers can tell which one answered.

  `permit_form_redirect/2` widens a `form-action` CSP directive to the redirect
  origin because Chromium and Safari also check it against the redirect that
  follows Approve; `'self'` alone silently blocks the callback everywhere but
  Firefox.
  """

  import Plug.Conn

  alias McpGatehouse.OAuth.Lookup
  alias McpGatehouse.OAuth.RedirectUri
  alias McpGatehouse.OAuth.Scopes
  alias McpGatehouse.OAuth.ServerActor
  alias McpGatehouse.Server.Callbacks

  defstruct [
    :client_id,
    :client_name,
    :redirect_uri,
    :redirect_host,
    :code_challenge,
    :state,
    :scopes
  ]

  @typedoc "A validated authorization request, ready for the consent page and `approve/3`."
  @type t :: %__MODULE__{
          client_id: String.t(),
          client_name: String.t(),
          redirect_uri: String.t(),
          redirect_host: String.t(),
          code_challenge: String.t(),
          state: String.t() | nil,
          scopes: [String.t()]
        }

  @typedoc "An OAuth error body, to answer with a 400."
  @type error :: %{error: String.t(), error_description: String.t()}

  @doc "Validates an authorization request's parameters."
  @spec validate(module(), map()) :: {:ok, t()} | {:error, error()}
  def validate(server, params) do
    with {:ok, client} <- registered_client(server, params["client_id"]),
         {:ok, redirect} <- registered_redirect(client, params["redirect_uri"]),
         :ok <- supported_response_type(params["response_type"]),
         :ok <- supported_challenge(params),
         :ok <- strings_or_absent(params, ["state", "scope"]) do
      {:ok,
       %__MODULE__{
         client_id: client.client_id,
         client_name: client.client_name || client.client_id,
         redirect_uri: params["redirect_uri"],
         redirect_host: redirect.host,
         code_challenge: params["code_challenge"],
         state: params["state"],
         scopes: Scopes.granted(params["scope"])
       }}
    end
  end

  @doc """
  Approves a validated request as `user`, returning the client callback URL to
  redirect to: with a `code`, with `error=access_denied` when `user` may not
  consent, or with `error=server_error` when the code could not be issued.
  """
  @spec approve(module(), t(), term()) :: {:ok, String.t()}
  def approve(server, %__MODULE__{} = authorization, user) do
    case server.consent_identity(user) do
      {:ok, user_id, company_id} -> issued(server, authorization, user_id, company_id)
      _not_permitted -> {:ok, callback_url(server, authorization, %{"error" => "access_denied"})}
    end
  end

  @doc """
  Declines a request, returning the client callback URL carrying
  `error=access_denied`. Only the client, its redirect URI and the `state` the
  callback carries back are checked: the decline has to reach the client even
  when the rest of the request is invalid.
  """
  @spec deny(module(), map()) :: {:ok, String.t()} | {:error, error()}
  def deny(server, params) do
    with {:ok, client} <- registered_client(server, params["client_id"]),
         {:ok, _redirect} <- registered_redirect(client, params["redirect_uri"]),
         :ok <- strings_or_absent(params, ["state"]) do
      callback = %{redirect_uri: params["redirect_uri"], state: params["state"]}

      {:ok, callback_url(server, callback, %{"error" => "access_denied"})}
    end
  end

  @doc """
  Adds the validated redirect origin to the response's `form-action` CSP
  directive. Leaves the response untouched when it has no `form-action`.
  """
  @spec permit_form_redirect(Plug.Conn.t(), t()) :: Plug.Conn.t()
  def permit_form_redirect(conn, %__MODULE__{redirect_uri: redirect_uri}) do
    with {:ok, redirect} <- RedirectUri.parse(redirect_uri),
         {:ok, origin} <- redirect_origin(redirect),
         [policy | _rest] <- get_resp_header(conn, "content-security-policy"),
         {:ok, widened} <- add_form_action_source(policy, origin) do
      put_resp_header(conn, "content-security-policy", widened)
    else
      _no_form_action -> conn
    end
  end

  defp issued(server, authorization, user_id, company_id) do
    case issue(server, authorization, user_id, company_id) do
      {:ok, %{__metadata__: %{code: code}}} ->
        {:ok, callback_url(server, authorization, %{"code" => code})}

      _unexpected ->
        {:ok, callback_url(server, authorization, %{"error" => "server_error"})}
    end
  end

  defp issue(server, authorization, user_id, company_id) do
    server.authorization_code_resource().issue(
      %{
        client_id: authorization.client_id,
        user_id: user_id,
        company_id: company_id,
        redirect_uri: authorization.redirect_uri,
        code_challenge: authorization.code_challenge,
        code_challenge_method: :S256,
        scopes: authorization.scopes
      },
      actor: ServerActor.new()
    )
  end

  defp registered_client(server, client_id) do
    case Lookup.fetch_client(server, client_id) do
      {:ok, client} -> {:ok, client}
      :error -> unknown_client()
    end
  end

  defp unknown_client do
    {:error,
     %{
       error: "invalid_client",
       error_description:
         "this client_id is not registered; discard any stored registration and register again at /mcp/oauth/register"
     }}
  end

  defp registered_redirect(%{redirect_uris: uris}, redirect_uri) do
    with true <- redirect_uri in uris,
         {:ok, redirect} <- RedirectUri.parse(redirect_uri) do
      {:ok, redirect}
    else
      false ->
        invalid_redirect("redirect_uri is not registered for this client")

      :error ->
        invalid_redirect("redirect_uri must have a plain host and no userinfo; register the client again")
    end
  end

  defp invalid_redirect(description), do: {:error, %{error: "invalid_redirect_uri", error_description: description}}

  defp supported_response_type(nil), do: :ok
  defp supported_response_type("code"), do: :ok

  defp supported_response_type(_response_type) do
    {:error, %{error: "unsupported_response_type", error_description: "response_type must be code"}}
  end

  defp supported_challenge(%{"code_challenge" => challenge, "code_challenge_method" => "S256"})
       when is_binary(challenge) and challenge != "", do: :ok

  defp supported_challenge(_params) do
    {:error, %{error: "invalid_request", error_description: "code_challenge with S256 is required"}}
  end

  defp strings_or_absent(params, names) do
    case Enum.find(names, &(not string_or_absent?(params[&1]))) do
      nil -> :ok
      name -> {:error, %{error: "invalid_request", error_description: "#{name} must be a string"}}
    end
  end

  defp string_or_absent?(value), do: is_nil(value) or is_binary(value)

  defp callback_url(server, %{redirect_uri: redirect_uri, state: state}, added) do
    uri = URI.parse(redirect_uri)

    query =
      (uri.query || "")
      |> URI.decode_query()
      |> Map.merge(added)
      |> maybe_state(state)
      |> Map.put("iss", Callbacks.issuer(server))
      |> URI.encode_query()

    URI.to_string(%{uri | query: query})
  end

  defp maybe_state(query, state) when is_binary(state), do: Map.put(query, "state", state)
  defp maybe_state(query, _no_state), do: query

  defp redirect_origin(%URI{scheme: scheme, host: host, port: port}) when scheme in ["https", "http"],
    do: {:ok, "#{scheme}://#{csp_host(host)}:#{port}"}

  defp redirect_origin(_uri), do: :error

  defp csp_host("::1"), do: "[::1]"
  defp csp_host(host), do: host

  defp add_form_action_source(policy, origin) do
    directives = policy |> String.split(";", trim: true) |> Enum.map(&String.trim/1)

    if Enum.any?(directives, &String.starts_with?(&1, "form-action ")),
      do: {:ok, Enum.map_join(directives, "; ", &add_form_action_directive_source(&1, origin))},
      else: :error
  end

  defp add_form_action_directive_source("form-action " <> sources, origin), do: "form-action #{sources} #{origin}"

  defp add_form_action_directive_source(directive, _origin), do: directive
end
