defmodule McpGatehouse.Test.Flow do
  @moduledoc """
  Drives `McpGatehouse.Test.Router` the way a remote MCP client does: register,
  authorize (through `McpGatehouse.OAuth.Authorization`, standing in for the
  host's consent controller), exchange, call `/mcp`, refresh and revoke.
  """

  import Plug.Conn
  import Plug.Test

  alias McpGatehouse.OAuth.Authorization
  alias McpGatehouse.OAuth.ServerActor
  alias McpGatehouse.Plug.Token
  alias McpGatehouse.Test.AccessToken
  alias McpGatehouse.Test.AuthorizationCode
  alias McpGatehouse.Test.Router
  alias McpGatehouse.Test.Server

  @redirect_uri "https://claude.ai/api/mcp/auth_callback"
  @protocol_version "2026-07-28"
  @meta_protocol_version "io.modelcontextprotocol/protocolVersion"
  @router_opts Router.init([])

  @spec redirect_uri() :: String.t()
  def redirect_uri, do: @redirect_uri

  @spec protocol_version() :: String.t()
  def protocol_version, do: @protocol_version

  @spec get(String.t(), [{String.t(), String.t()}]) :: Plug.Conn.t()
  def get(path, headers \\ []) do
    :get |> conn(path) |> with_headers(headers) |> Router.call(@router_opts)
  end

  @spec post_json(String.t(), map(), [{String.t(), String.t()}]) :: Plug.Conn.t()
  def post_json(path, body, headers \\ []) do
    :post
    |> conn(path, Jason.encode!(body))
    |> put_req_header("content-type", "application/json")
    |> with_headers(headers)
    |> Router.call(@router_opts)
  end

  @spec post_form(String.t(), map()) :: Plug.Conn.t()
  def post_form(path, params) do
    :post
    |> conn(path, URI.encode_query(params))
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> Router.call(@router_opts)
  end

  @spec json(Plug.Conn.t()) :: term()
  def json(conn), do: Jason.decode!(conn.resp_body)

  @spec register(map()) :: map()
  def register(params \\ %{}) do
    "/mcp/oauth/register"
    |> post_json(Map.merge(%{"client_name" => "Claude", "redirect_uris" => [@redirect_uri]}, params))
    |> json()
  end

  @spec pkce() :: {String.t(), String.t()}
  def pkce do
    verifier = 64 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
    challenge = :sha256 |> :crypto.hash(verifier) |> Base.url_encode64(padding: false)

    {verifier, challenge}
  end

  @spec authorize_params(String.t(), String.t(), map()) :: map()
  def authorize_params(client_id, challenge, overrides \\ %{}) do
    Map.merge(
      %{
        "response_type" => "code",
        "client_id" => client_id,
        "redirect_uri" => @redirect_uri,
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "state" => "opaque-state",
        "scope" => "mcp:read"
      },
      overrides
    )
  end

  @doc "Validates and approves as `user`, returning the callback URL the user is sent to."
  @spec approve(String.t(), String.t(), term(), map()) :: String.t()
  def approve(client_id, challenge, user, overrides \\ %{}) do
    {:ok, authorization} =
      Authorization.validate(Server, authorize_params(client_id, challenge, overrides))

    {:ok, callback} = Authorization.approve(Server, authorization, user)

    callback
  end

  @spec query(String.t()) :: map()
  def query(url), do: url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

  @spec exchange_code(String.t(), String.t(), String.t(), map()) :: Plug.Conn.t()
  def exchange_code(client_id, code, verifier, overrides \\ %{}) do
    post_form(
      "/mcp/oauth/token",
      Map.merge(
        %{
          "grant_type" => "authorization_code",
          "code" => code,
          "code_verifier" => verifier,
          "client_id" => client_id,
          "redirect_uri" => @redirect_uri
        },
        overrides
      )
    )
  end

  @spec refresh(String.t(), String.t()) :: Plug.Conn.t()
  def refresh(client_id, refresh_token) do
    post_form("/mcp/oauth/token", %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token,
      "client_id" => client_id
    })
  end

  @doc """
  The same refresh straight through `McpGatehouse.Plug.Token` built for
  `server`, so a test can pick the host's callbacks and resources per request.
  """
  @spec refresh_through(module(), String.t(), String.t()) :: Plug.Conn.t()
  def refresh_through(server, client_id, refresh_token) do
    :post
    |> conn("/mcp/oauth/token", %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token,
      "client_id" => client_id
    })
    |> Token.call(Token.init(server: server))
  end

  @spec revoke(map()) :: Plug.Conn.t()
  def revoke(params), do: post_form("/mcp/oauth/revoke", params)

  @doc "Runs the whole flow for `user` and returns the client id and the token response."
  @spec connect(term()) :: %{client_id: String.t(), tokens: map()}
  def connect(user) do
    %{"client_id" => client_id} = register()
    {verifier, challenge} = pkce()
    %{"code" => code} = client_id |> approve(challenge, user) |> query()

    %{client_id: client_id, tokens: client_id |> exchange_code(code, verifier) |> json()}
  end

  @doc "Mints a token row directly, as the token endpoint would, for `user`."
  @spec mint(term(), keyword()) :: struct()
  def mint(user, opts \\ []) do
    {:ok, minted} =
      AccessToken.mint(
        %{
          client_id: Keyword.get(opts, :client_id, "test-client"),
          user_id: user.id,
          company_id: Keyword.get(opts, :company_id, user.company_id),
          scopes: Keyword.get(opts, :scopes, ["mcp:read"]),
          expires_in: Keyword.get(opts, :expires_in, 3600)
        },
        actor: ServerActor.new()
      )

    minted
  end

  @doc "What the consent step issues a code with for `user`, leaving the challenge method to its default."
  @spec code_attrs(term()) :: map()
  def code_attrs(user) do
    %{
      client_id: "test-client",
      user_id: user.id,
      company_id: user.company_id,
      redirect_uri: "https://claude.ai/cb",
      code_challenge: "challenge",
      scopes: ["mcp:read"]
    }
  end

  @doc "Issues an authorization code row directly, as the consent step would, for `user`."
  @spec issue_code(term()) :: struct()
  def issue_code(user) do
    {:ok, issued} = AuthorizationCode.issue(code_attrs(user), actor: ServerActor.new())

    issued
  end

  @spec request_meta() :: map()
  def request_meta do
    %{
      @meta_protocol_version => @protocol_version,
      "io.modelcontextprotocol/clientInfo" => %{"name" => "claude-desktop", "version" => "9.9.9"},
      "io.modelcontextprotocol/clientCapabilities" => %{}
    }
  end

  @doc "A 2026-07-28 JSON-RPC request to `/mcp` through the test router."
  @spec rpc(String.t(), map(), String.t() | nil, [{String.t(), String.t()}]) :: Plug.Conn.t()
  def rpc(method, params, token, headers \\ []) do
    :post
    |> conn("/mcp", Jason.encode!(rpc_body(method, params)))
    |> rpc_headers(method, params, token, headers)
    |> Router.call(@router_opts)
  end

  @doc """
  The same request through the `:mcp` plugs built for `server`, so a test can
  pick the host's optional callbacks per request, serving `tools`.
  """
  @spec rpc_through(module(), String.t(), map(), String.t() | nil, [atom()]) :: Plug.Conn.t()
  def rpc_through(server, method, params, token, tools \\ [:list_widgets, :report_missing_capability]) do
    :post
    |> conn("/", Jason.encode!(rpc_body(method, params)))
    |> rpc_headers(method, params, token, [])
    |> run([
      {McpGatehouse.Plug.Bearer, server: server},
      {McpGatehouse.Plug.Analytics, server: server},
      {AshAi.Mcp.Router, tools: tools, otp_app: :mcp_gatehouse}
    ])
  end

  @doc "Whether `access_token` still authenticates a `tools/list` at `/mcp`."
  @spec authenticates?(String.t()) :: boolean()
  def authenticates?(access_token), do: rpc("tools/list", %{}, access_token).status == 200

  @spec call_tool(String.t(), map(), String.t()) :: map()
  def call_tool(name, arguments, token) do
    "tools/call"
    |> rpc(%{"name" => name, "arguments" => arguments}, token)
    |> json()
    |> Map.fetch!("result")
  end

  defp rpc_body(method, params) do
    %{
      "jsonrpc" => "2.0",
      "id" => "test_1",
      "method" => method,
      "params" => Map.put_new(params, "_meta", request_meta())
    }
  end

  defp rpc_headers(conn, method, params, token, headers) do
    conn
    |> put_req_header("content-type", "application/json")
    |> put_req_header("mcp-protocol-version", @protocol_version)
    |> put_req_header("mcp-method", method)
    |> with_tool_name(params)
    |> with_token(token)
    |> with_headers(headers)
  end

  defp with_tool_name(conn, %{"name" => name}), do: put_req_header(conn, "mcp-name", name)
  defp with_tool_name(conn, _params), do: conn

  defp with_token(conn, nil), do: conn
  defp with_token(conn, token), do: put_req_header(conn, "authorization", "Bearer #{token}")

  defp with_headers(conn, headers),
    do: Enum.reduce(headers, conn, fn {name, value}, acc -> put_req_header(acc, name, value) end)

  defp run(conn, plugs) do
    Enum.reduce_while(plugs, conn, fn {plug, opts}, acc ->
      case plug.call(acc, plug.init(opts)) do
        %Plug.Conn{halted: true} = halted -> {:halt, halted}
        continued -> {:cont, continued}
      end
    end)
  end
end
