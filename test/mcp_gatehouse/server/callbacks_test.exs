defmodule McpGatehouse.Server.CallbacksTest do
  @moduledoc """
  A host implements only what differs from the defaults. URLs go through the
  endpoint's `path/1`, so a host mounted under a path prefix advertises it,
  while the issuer is the endpoint URL exactly.
  """
  use ExUnit.Case, async: true

  alias McpGatehouse.Server.Callbacks
  alias McpGatehouse.Test.ConfiguredServer
  alias McpGatehouse.Test.LazyServer
  alias McpGatehouse.Test.MinimalServer
  alias McpGatehouse.Test.UnconfiguredServer
  alias McpGatehouse.Test.User

  defmodule PrefixedEndpoint do
    @moduledoc "A Phoenix endpoint mounted under `/app`, as `url: [path: \"/app\"]` configures one."

    def url, do: "https://mcp.example.test"
    def path(path), do: "/app" <> path
  end

  defmodule PrefixedServer do
    @moduledoc "A host server reduced to `endpoint/0`, the only callback URL building reads."

    def endpoint, do: PrefixedEndpoint
  end

  test "a server implementing only the required callbacks gets every default" do
    assert Callbacks.context(MinimalServer, %{}) == %{}
    assert Callbacks.analytics_payloads(MinimalServer) == :input
    assert Callbacks.trusted_proxies(MinimalServer) == []
    assert Callbacks.refresh_idle_ttl(MinimalServer) == 90 * 24 * 3600
  end

  test "filtered parameters default to the OTP app's configured list" do
    assert Callbacks.filtered_parameters(MinimalServer) ==
             ~w(password token secret code_verifier code_challenge iban)
  end

  test "filtered parameters fall back to the credential names when the app configures none" do
    assert Callbacks.filtered_parameters(UnconfiguredServer) ==
             ~w(password token secret code_verifier code_challenge)
  end

  test "a server's own answers win" do
    assert Callbacks.context(ConfiguredServer, %{}) == %{
             api?: true,
             mcp_scopes: ["mcp:read", "mcp:write"]
           }

    assert Callbacks.filtered_parameters(ConfiguredServer) == ["fuel", "apiKey"]
    assert Callbacks.analytics_payloads(ConfiguredServer) == :full
    assert Callbacks.trusted_proxies(ConfiguredServer) == ["35.191.0.0/16"]
    assert Callbacks.refresh_idle_ttl(ConfiguredServer) == 60
  end

  test "an optional callback counts even before its module is loaded" do
    :code.purge(LazyServer)
    :code.delete(LazyServer)
    refute :erlang.module_loaded(LazyServer)

    assert Callbacks.refresh_idle_ttl(LazyServer) == 42
  end

  test "URLs are the endpoint's, and the issuer has nothing appended" do
    assert Callbacks.url(MinimalServer, "/mcp") == "https://mcp.example.test/mcp"
    assert Callbacks.issuer(MinimalServer) == "https://mcp.example.test"
  end

  test "URLs carry the endpoint's path prefix, and the issuer still has nothing appended" do
    assert Callbacks.url(PrefixedServer, "/mcp") == "https://mcp.example.test/app/mcp"
    assert Callbacks.issuer(PrefixedServer) == "https://mcp.example.test"
  end

  describe "load_owner/3" do
    test "accepts a loaded user of the grant's company" do
      user = User.admin()

      assert {:ok, %User{id: id}} = Callbacks.load_owner(MinimalServer, user.id, user.company_id)
      assert id == user.id
    end

    test "refuses a missing, nil or foreign user" do
      company_id = Ash.UUID.generate()

      for user_id <- [User.unloadable_id(), User.loads_as_nil_id(), User.in_other_company_id()] do
        assert Callbacks.load_owner(MinimalServer, user_id, company_id) == :error
      end
    end
  end
end
