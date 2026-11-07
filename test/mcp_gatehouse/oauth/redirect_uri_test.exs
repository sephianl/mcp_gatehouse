defmodule McpGatehouse.OAuth.RedirectUriTest do
  @moduledoc """
  The strict redirect URI parse: whatever it accepts, a browser sends the user
  to the host it reports, so the consent page cannot be made to name another.
  """
  use ExUnit.Case, async: true

  alias McpGatehouse.OAuth.RedirectUri

  test "accepts plain https and loopback URIs, reporting the host a browser uses" do
    for {uri, host} <- [
          {"https://claude.ai/api/mcp/auth_callback", "claude.ai"},
          {"https://claude.ai/cb?tenant=acme", "claude.ai"},
          {"http://127.0.0.1:33418/callback", "127.0.0.1"},
          {"http://localhost:33418/callback", "localhost"},
          {"http://[::1]:33418/callback", "::1"}
        ] do
      assert {:ok, %URI{host: ^host}} = RedirectUri.parse(uri)
    end
  end

  test "refuses a backslash, which browsers read as a slash and URI.parse/1 does not" do
    assert URI.parse("https://evil.example\\@claude.ai/cb").host == "claude.ai"

    assert RedirectUri.parse("https://evil.example\\@claude.ai/cb") == :error
    assert RedirectUri.parse("http://evil.example\\@localhost:3334/cb") == :error
    assert RedirectUri.parse("https://claude.ai/cb\\x") == :error
  end

  test "refuses userinfo, encoded or non-plain hosts, and no host at all" do
    for uri <- [
          "https://claude.ai@evil.example/cb",
          "https://@claude.ai/cb",
          "https://evil%2Eexample/cb",
          "https://[fe80::1]/cb",
          "https:///cb",
          "https:claude.ai/cb",
          "https://claude.ai/c b",
          "https://claudé.ai/cb"
        ] do
      assert RedirectUri.parse(uri) == :error, uri
    end
  end

  test "refuses anything that is not a string" do
    for uri <- [nil, ["https://claude.ai/cb"], %{}, 1] do
      assert RedirectUri.parse(uri) == :error
    end
  end
end
