defmodule McpGatehouse.PhoenixRouterTest do
  @moduledoc """
  The documented router wiring, compiled by Phoenix rather than `Plug.Router`:
  `McpGatehouse.Test.PhoenixRouter` copies README §4, every route answers
  through it, and README §4 and the `McpGatehouse` overview still match it
  statement for statement. A wiring that only works in `Plug.Router` (such as a
  two-argument `post`) fails here instead of in a host.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias McpGatehouse.OAuth.Authorization
  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.PhoenixEndpoint
  alias McpGatehouse.Test.Server
  alias McpGatehouse.Test.User

  @endpoint_opts PhoenixEndpoint.init([])
  @router_source "test/support/phoenix_router.ex"
  @doc_names [
    {"MyAppWeb.Mcp", "McpGatehouse.Test.Server"},
    {":my_app", ":mcp_gatehouse"},
    {~s("My App"), ~s("Test MCP")}
  ]

  defp request(conn), do: PhoenixEndpoint.call(conn, @endpoint_opts)

  defp post_json(path, body) do
    :post
    |> conn(path, Jason.encode!(body))
    |> put_req_header("content-type", "application/json")
    |> request()
  end

  defp post_form(path, params) do
    :post
    |> conn(path, URI.encode_query(params))
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> request()
  end

  defp tools_list(token) do
    body = %{
      "jsonrpc" => "2.0",
      "id" => "phoenix_1",
      "method" => "tools/list",
      "params" => %{"_meta" => Flow.request_meta()}
    }

    :post
    |> conn("/mcp", Jason.encode!(body))
    |> put_req_header("content-type", "application/json")
    |> put_req_header("mcp-protocol-version", Flow.protocol_version())
    |> put_req_header("mcp-method", "tools/list")
    |> put_req_header("authorization", "Bearer #{token}")
    |> request()
  end

  describe "routes" do
    test "serve both discovery documents" do
      resource = :get |> conn("/.well-known/oauth-protected-resource") |> request()
      server = :get |> conn("/.well-known/oauth-authorization-server") |> request()

      assert resource.status == 200
      assert Flow.json(resource)["resource"] == "https://mcp.example.test/mcp"
      assert server.status == 200
      assert Flow.json(server)["issuer"] == "https://mcp.example.test"
    end

    test "answer an unsupported grant type and an unauthenticated /mcp call" do
      token = post_form("/mcp/oauth/token", %{"grant_type" => "password"})

      assert token.status == 400
      assert Flow.json(token) == %{"error" => "unsupported_grant_type"}

      unauthenticated =
        :post
        |> conn("/mcp", "{}")
        |> put_req_header("content-type", "application/json")
        |> request()

      assert unauthenticated.status == 401

      assert get_resp_header(unauthenticated, "www-authenticate") == [
               ~s(Bearer resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource")
             ]
    end

    test "carry a client through register, exchange, tools/list, refresh and revoke" do
      registered =
        post_json("/mcp/oauth/register", %{
          "client_name" => "Claude",
          "redirect_uris" => [Flow.redirect_uri()]
        })

      assert registered.status == 201
      %{"client_id" => client_id} = Flow.json(registered)

      {verifier, challenge} = Flow.pkce()

      {:ok, authorization} =
        Authorization.validate(Server, Flow.authorize_params(client_id, challenge))

      {:ok, callback} = Authorization.approve(Server, authorization, User.admin())

      exchanged =
        post_form("/mcp/oauth/token", %{
          "grant_type" => "authorization_code",
          "code" => Flow.query(callback)["code"],
          "code_verifier" => verifier,
          "client_id" => client_id,
          "redirect_uri" => Flow.redirect_uri()
        })

      assert exchanged.status == 200
      tokens = Flow.json(exchanged)

      listed = tools_list(tokens["access_token"])
      assert listed.status == 200
      assert [_first | _rest] = get_in(Flow.json(listed), ["result", "tools"])
      assert_received {:captured, "$mcp_tools_list", _distinct_id, _company_id, _properties}

      refreshed =
        post_form("/mcp/oauth/token", %{
          "grant_type" => "refresh_token",
          "refresh_token" => tokens["refresh_token"],
          "client_id" => client_id
        })

      assert refreshed.status == 200
      %{"access_token" => access_token} = Flow.json(refreshed)

      revoked =
        post_form("/mcp/oauth/revoke", %{"token" => access_token, "client_id" => client_id})

      assert revoked.status == 200
      assert tools_list(access_token).status == 401
    end
  end

  describe "the documented wiring" do
    test "README §4 wires the library exactly as the Phoenix test router does" do
      [_before, section] = "README.md" |> File.read!() |> String.split("### 4. Router", parts: 2)
      [_prose, code] = String.split(section, "```elixir\n", parts: 2)
      [code, _rest] = String.split(code, "```", parts: 2)

      assert doc_wiring(code) == router_wiring()
    end

    test "the McpGatehouse overview wires the library exactly as the Phoenix test router does" do
      {:docs_v1, _anno, _language, _format, %{"en" => moduledoc}, _metadata, _docs} =
        Code.fetch_docs(McpGatehouse)

      assert moduledoc |> indented_block_from("pipeline :mcp_oauth do") |> doc_wiring() ==
               router_wiring()
    end
  end

  defp doc_wiring(code) do
    @doc_names
    |> Enum.reduce(code, fn {doc_name, test_name}, acc ->
      String.replace(acc, doc_name, test_name)
    end)
    |> Code.string_to_quoted!()
    |> library_wiring(%{})
  end

  defp router_wiring do
    {:defmodule, _meta, [{:__aliases__, _alias_meta, [:McpGatehouse, :Test, :PhoenixRouter]}, [do: body]]} =
      @router_source |> File.read!() |> Code.string_to_quoted!() |> statements() |> hd()

    aliases =
      for {:alias, _meta, [{:__aliases__, _alias_meta, parts}]} <- statements(body),
          into: %{},
          do: {List.last(parts), parts}

    library_wiring(body, aliases)
  end

  defp library_wiring(ast, aliases) do
    ast
    |> statements()
    |> Enum.filter(&library_wiring?/1)
    |> Enum.map(&normalize(&1, aliases))
  end

  defp statements({:__block__, _meta, statements}), do: statements
  defp statements(statement), do: [statement]

  defp library_wiring?({:pipeline, _meta, [name, _block]}), do: name in [:mcp_oauth, :mcp]
  defp library_wiring?({:scope, _meta, [_path, [do: _block]]}), do: true
  defp library_wiring?(_statement), do: false

  defp normalize(statement, aliases) do
    statement
    |> Macro.prewalk(fn
      {:__aliases__, _meta, [single]} when is_map_key(aliases, single) ->
        {:__aliases__, [], aliases[single]}

      node ->
        Macro.update_meta(node, fn _meta -> [] end)
    end)
    |> Macro.to_string()
  end

  defp indented_block_from(text, first_line) do
    [before, rest] = String.split(text, first_line, parts: 2)
    [indent] = Regex.run(~r/ *\z/, before)

    lines =
      rest
      |> String.split("\n")
      |> Enum.take_while(&(&1 == "" or String.starts_with?(&1, indent)))

    Enum.join([first_line | lines], "\n")
  end
end
