defmodule McpGatehouse.Plug.MetadataTest do
  @moduledoc """
  A remote MCP client bootstraps entirely from these two documents: it reads the
  protected-resource metadata to find the authorization server, then the
  authorization-server metadata to find where to send the user and how to
  register itself. Both must be served without a credential, because the client
  has none yet, and the issuer must be exactly what earlier clients were given.
  """
  use ExUnit.Case, async: true

  alias McpGatehouse.Plug.Metadata
  alias McpGatehouse.Test.Flow

  @base "https://mcp.example.test"

  test "protected resource metadata names the MCP endpoint as the resource" do
    conn = Flow.get("/.well-known/oauth-protected-resource")

    assert conn.status == 200

    assert Flow.json(conn) == %{
             "resource" => @base <> "/mcp",
             "authorization_servers" => [@base],
             "scopes_supported" => ["mcp:read"],
             "bearer_methods_supported" => ["header"]
           }
  end

  test "authorization server metadata advertises the endpoints, PKCE and the iss parameter" do
    conn = Flow.get("/.well-known/oauth-authorization-server")

    assert conn.status == 200

    assert Flow.json(conn) == %{
             "issuer" => @base,
             "authorization_endpoint" => @base <> "/mcp/oauth/authorize",
             "token_endpoint" => @base <> "/mcp/oauth/token",
             "registration_endpoint" => @base <> "/mcp/oauth/register",
             "revocation_endpoint" => @base <> "/mcp/oauth/revoke",
             "response_types_supported" => ["code"],
             "grant_types_supported" => ["authorization_code", "refresh_token"],
             "code_challenge_methods_supported" => ["S256"],
             "token_endpoint_auth_methods_supported" => ["none"],
             "scopes_supported" => ["mcp:read"],
             "authorization_response_iss_parameter_supported" => true
           }
  end

  test "discovery documents stay cacheable" do
    for path <- [
          "/.well-known/oauth-protected-resource",
          "/.well-known/oauth-authorization-server"
        ] do
      conn = Flow.get(path)

      refute "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
      assert Plug.Conn.get_resp_header(conn, "pragma") == []
      assert ["application/json" <> _charset] = Plug.Conn.get_resp_header(conn, "content-type")
    end
  end

  test "init refuses an unknown document" do
    assert_raise ArgumentError, ~r/document/, fn ->
      Metadata.init(server: McpGatehouse.Test.Server, document: :openid_configuration)
    end
  end
end
