defmodule McpGatehouse.Plug.RegistrationTest do
  @moduledoc """
  RFC 7591 dynamic client registration. Remote MCP clients self-register on
  first connection, so this endpoint is necessarily open — which makes the
  redirect-uri check the only thing standing between us and an open redirector.
  """
  use ExUnit.Case, async: true

  alias McpGatehouse.Test.Flow

  defp register(params), do: Flow.post_json("/mcp/oauth/register", params)

  defp assert_refused(conn) do
    assert conn.status == 400

    assert Flow.json(conn) == %{
             "error" => "invalid_redirect_uri",
             "error_description" =>
               "redirect_uris must be 1 to 10 https URIs (http only on loopback) of at most 2000 characters, " <>
                 "with a plain host and no userinfo or fragment"
           }
  end

  test "registers a public client and returns no secret" do
    conn =
      register(%{
        "client_name" => "Claude",
        "redirect_uris" => ["https://claude.ai/api/mcp/auth_callback"],
        "token_endpoint_auth_method" => "client_secret_basic"
      })

    assert conn.status == 201
    body = Flow.json(conn)

    assert is_binary(body["client_id"])
    assert is_integer(body["client_id_issued_at"])
    assert body["client_name"] == "Claude"
    assert body["redirect_uris"] == ["https://claude.ai/api/mcp/auth_callback"]
    assert body["token_endpoint_auth_method"] == "none"
    assert body["grant_types"] == ["authorization_code", "refresh_token"]
    assert body["response_types"] == ["code"]
    assert body["scope"] == "mcp:read"
    refute Map.has_key?(body, "client_secret")
  end

  test "registration needs no credential and forbids storage" do
    conn = register(%{"redirect_uris" => ["https://claude.ai/cb"]})

    assert conn.status == 201
    assert Plug.Conn.get_resp_header(conn, "cache-control") == ["no-store"]
    assert Plug.Conn.get_resp_header(conn, "pragma") == ["no-cache"]
  end

  test "rejects a registration with no redirect uri" do
    assert_refused(register(%{"client_name" => "No Redirect"}))
    assert_refused(register(%{"redirect_uris" => []}))
    assert_refused(register(%{"redirect_uris" => "https://claude.ai/cb"}))
  end

  test "rejects a non-https redirect uri" do
    assert_refused(register(%{"redirect_uris" => ["http://evil.example/cb"]}))
    assert_refused(register(%{"redirect_uris" => ["https://claude.ai/cb", "ftp://claude.ai/cb"]}))
    assert_refused(register(%{"redirect_uris" => ["https:///cb"]}))
  end

  test "rejects a redirect uri with a fragment" do
    assert_refused(register(%{"redirect_uris" => ["https://claude.ai/cb#frag"]}))
    assert_refused(register(%{"redirect_uris" => ["https://claude.ai/cb#"]}))
    assert_refused(register(%{"redirect_uris" => ["http://127.0.0.1:33418/callback#x"]}))
  end

  test "rejects a redirect uri a browser would send somewhere other than the host it shows" do
    assert_refused(register(%{"redirect_uris" => ["https://evil.example\\@claude.ai/cb"]}))
    assert_refused(register(%{"redirect_uris" => ["http://evil.example\\@localhost/cb"]}))
    assert_refused(register(%{"redirect_uris" => ["https://claude.ai@evil.example/cb"]}))
    assert_refused(register(%{"redirect_uris" => ["https://@claude.ai/cb"]}))
    assert_refused(register(%{"redirect_uris" => ["https://evil%2Eexample/cb"]}))
    assert_refused(register(%{"redirect_uris" => ["https:claude.ai/cb"]}))
  end

  test "caps the number and length of redirect uris" do
    ten = for n <- 1..10, do: "https://claude.ai/cb/#{n}"
    assert register(%{"redirect_uris" => ten}).status == 201
    assert_refused(register(%{"redirect_uris" => ["https://claude.ai/cb/0" | ten]}))

    long = "https://claude.ai/" <> String.duplicate("a", 2000 - 18)
    assert register(%{"redirect_uris" => [long]}).status == 201
    assert_refused(register(%{"redirect_uris" => [long <> "a"]}))
  end

  test "refuses a client name over 200 characters as invalid client metadata" do
    assert register(%{
             "client_name" => String.duplicate("n", 200),
             "redirect_uris" => ["https://claude.ai/cb"]
           }).status ==
             201

    for name <- [String.duplicate("n", 201), %{"name" => "Claude"}] do
      conn = register(%{"client_name" => name, "redirect_uris" => ["https://claude.ai/cb"]})

      assert conn.status == 400

      assert Flow.json(conn) == %{
               "error" => "invalid_client_metadata",
               "error_description" => "client_name must be a string of at most 200 characters"
             }
    end
  end

  test "a bad redirect uri is reported as such even when the client name is refused too" do
    assert_refused(
      register(%{
        "client_name" => String.duplicate("n", 201),
        "redirect_uris" => ["http://evil.example/cb"]
      })
    )
  end

  test "allows http only for loopback, so local IDE clients still work" do
    assert register(%{"redirect_uris" => ["http://127.0.0.1:33418/callback"]}).status == 201
    assert register(%{"redirect_uris" => ["http://localhost:33418/callback"]}).status == 201
    assert register(%{"redirect_uris" => ["http://[::1]:33418/callback"]}).status == 201
  end

  test "each registration gets its own client id" do
    one = Flow.json(register(%{"redirect_uris" => ["https://a.example/cb"]}))
    two = Flow.json(register(%{"redirect_uris" => ["https://b.example/cb"]}))

    refute one["client_id"] == two["client_id"]
  end

  test "an unknown requested scope is narrowed to the granted one" do
    body =
      Flow.json(register(%{"redirect_uris" => ["https://a.example/cb"], "scope" => "admin mcp:write"}))

    assert body["scope"] == "mcp:read"
  end

  test "a scope that is not a string is narrowed to the granted one, not a crash" do
    for scope <- [["mcp:read"], %{"mcp:read" => true}, 1] do
      conn = register(%{"redirect_uris" => ["https://a.example/cb"], "scope" => scope})

      assert conn.status == 201
      assert Flow.json(conn)["scope"] == "mcp:read"
    end
  end
end
