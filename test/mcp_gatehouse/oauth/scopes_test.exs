defmodule McpGatehouse.OAuth.ScopesTest do
  @moduledoc """
  A requested scope string is narrowed to what is granted, never rejected
  (RFC 6749 §3.3), and an MCP token is never granted more than `mcp:read` today.
  """
  use ExUnit.Case, async: true

  alias McpGatehouse.OAuth.Scopes

  test "only mcp:read exists" do
    assert Scopes.read() == "mcp:read"
    assert Scopes.all() == ["mcp:read"]
  end

  test "an absent or empty request is granted mcp:read" do
    assert Scopes.granted(nil) == ["mcp:read"]
    assert Scopes.granted("") == ["mcp:read"]
  end

  test "unknown scopes are dropped" do
    assert Scopes.granted("mcp:read  mcp:write\tadmin") == ["mcp:read"]
    assert Scopes.granted("openid profile") == ["mcp:read"]
  end

  test "a request that is not a string is granted mcp:read" do
    assert Scopes.granted(["mcp:read", "mcp:write"]) == ["mcp:read"]
    assert Scopes.granted(%{"scope" => "mcp:read"}) == ["mcp:read"]
  end
end
