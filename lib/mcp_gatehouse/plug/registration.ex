defmodule McpGatehouse.Plug.Registration do
  @moduledoc """
  RFC 7591 dynamic client registration.

      post "/mcp/oauth/register", McpGatehouse.Plug.Registration, []

  in a scope piped through a pipeline that starts with `McpGatehouse.Plug.Server`.

  Open by necessity: a remote MCP client has no credential when it first
  reaches us. The client resource forbids every action to anyone but
  `McpGatehouse.OAuth.ServerActor`, so this is the single place registration
  can happen, and the redirect-uri validation on the resource is what keeps it
  from becoming an open redirector. Every client is public: no secret is issued
  whatever `token_endpoint_auth_method` asks for.

  A refusal is a 400 with `invalid_redirect_uri`, or `invalid_client_metadata`
  when the redirect URIs are fine and only `client_name` was refused (not a
  string, or longer than 200 characters).

  The response is marked `no-store`. The host's endpoint must parse JSON bodies.
  """
  @behaviour Plug

  alias McpGatehouse.OAuth.Scopes
  alias McpGatehouse.OAuth.ServerActor
  alias McpGatehouse.Plug.Json
  alias McpGatehouse.Plug.NoStore
  alias McpGatehouse.Plug.Options

  @impl Plug
  @spec init(keyword()) :: map()
  def init(opts), do: Options.validate(__MODULE__, opts)

  @impl Plug
  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, opts) do
    clients = Options.server(conn, __MODULE__, opts).client_resource()
    conn = NoStore.call(conn, [])

    conn.params
    |> registration_attrs()
    |> clients.register(actor: ServerActor.new())
    |> respond(conn)
  end

  defp registration_attrs(params) do
    %{
      client_name: params["client_name"],
      redirect_uris: params["redirect_uris"],
      token_endpoint_auth_method: :none,
      scopes: Scopes.granted(params["scope"])
    }
  end

  defp respond({:ok, client}, conn) do
    Json.send_json(conn, 201, %{
      client_id: client.client_id,
      client_id_issued_at: DateTime.to_unix(client.created_at),
      client_name: client.client_name,
      redirect_uris: client.redirect_uris,
      token_endpoint_auth_method: to_string(client.token_endpoint_auth_method),
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      scope: Enum.join(client.scopes, " ")
    })
  end

  defp respond({:error, error}, conn) do
    if only_client_name_refused?(error) do
      Json.send_json(conn, 400, %{
        error: "invalid_client_metadata",
        error_description: "client_name must be a string of at most 200 characters"
      })
    else
      Json.send_json(conn, 400, %{
        error: "invalid_redirect_uri",
        error_description:
          "redirect_uris must be 1 to 10 https URIs (http only on loopback) of at most 2000 characters, " <>
            "with a plain host and no userinfo or fragment"
      })
    end
  end

  defp only_client_name_refused?(%Ash.Error.Invalid{errors: [_first | _rest] = errors}),
    do: Enum.all?(errors, &match?(%{field: :client_name}, &1))

  defp only_client_name_refused?(_error), do: false
end
