defmodule McpGatehouse.Plug.Metadata do
  @moduledoc """
  The two discovery documents a remote MCP client reads before it holds any
  credential: RFC 9728 protected-resource metadata and RFC 8414
  authorization-server metadata.

      get "/oauth-protected-resource", McpGatehouse.Plug.Metadata, document: :protected_resource
      get "/oauth-authorization-server", McpGatehouse.Plug.Metadata, document: :authorization_server

  in a scope piped through a pipeline that starts with `McpGatehouse.Plug.Server`
  (see there for why the route itself names no server).

  `resource` must equal the URL the user typed into their client character for
  character, or the client rejects the server — which is why it is derived from
  the endpoint rather than configured separately. `issuer` and
  `authorization_servers` are the endpoint URL exactly, with nothing appended.

  `authorization_response_iss_parameter_supported` advertises the RFC 9207 `iss`
  parameter `McpGatehouse.OAuth.Authorization` adds to every callback.

  Both documents are left cacheable.
  """
  @behaviour Plug

  alias McpGatehouse.OAuth.Scopes
  alias McpGatehouse.Plug.Json
  alias McpGatehouse.Plug.Options
  alias McpGatehouse.Server.Callbacks

  @schema [
    document: [type: {:in, [:protected_resource, :authorization_server]}, required: true]
  ]

  @impl Plug
  @spec init(keyword()) :: map()
  def init(opts), do: Options.validate(__MODULE__, @schema, opts)

  @impl Plug
  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, %{document: document} = opts),
    do: Json.send_json(conn, 200, document(document, Options.server(conn, __MODULE__, opts)))

  defp document(:protected_resource, server) do
    %{
      resource: Callbacks.url(server, "/mcp"),
      authorization_servers: [Callbacks.issuer(server)],
      scopes_supported: Scopes.all(),
      bearer_methods_supported: ["header"]
    }
  end

  defp document(:authorization_server, server) do
    %{
      issuer: Callbacks.issuer(server),
      authorization_endpoint: Callbacks.url(server, "/mcp/oauth/authorize"),
      token_endpoint: Callbacks.url(server, "/mcp/oauth/token"),
      registration_endpoint: Callbacks.url(server, "/mcp/oauth/register"),
      revocation_endpoint: Callbacks.url(server, "/mcp/oauth/revoke"),
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: Scopes.all(),
      authorization_response_iss_parameter_supported: true
    }
  end
end
