defmodule McpGatehouse.Plug.BearerTest do
  @moduledoc """
  The MCP endpoint resolves its actor and tenant from an MCP token and nothing
  else. Every way a credential can be missing, wrong or stale is a 401 that
  points the client at its metadata, and a host loader that returns the wrong
  user cannot authenticate across companies.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias Ash.PlugHelpers
  alias McpGatehouse.OAuth.ServerActor
  alias McpGatehouse.Plug.Bearer
  alias McpGatehouse.Test.AccessToken
  alias McpGatehouse.Test.ConfiguredServer
  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.Server
  alias McpGatehouse.Test.User

  @metadata ~s(resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource")

  defp list_with_header(value) do
    Flow.rpc("tools/list", %{}, nil, [{"authorization", value}])
  end

  defp assert_challenged(conn, error?) do
    assert conn.status == 401
    assert conn.halted
    assert Flow.json(conn) == %{"error" => "invalid_token"}

    expected =
      if error?, do: ~s(Bearer #{@metadata}, error="invalid_token"), else: ~s(Bearer #{@metadata})

    assert get_resp_header(conn, "www-authenticate") == [expected]
  end

  defp token_for(user, opts \\ []), do: Flow.mint(user, opts).__metadata__.token

  test "a request without a credential is challenged without an error code" do
    assert_challenged(Flow.rpc("tools/list", %{}, nil), false)
  end

  test "a non-bearer credential is challenged without an error code" do
    assert_challenged(list_with_header("Basic dXNlcjpwYXNz"), false)
    assert_challenged(list_with_header("Bearer "), false)
  end

  test "an unknown token is rejected" do
    assert_challenged(Flow.rpc("tools/list", %{}, "not-a-real-token"), true)
  end

  test "a refresh token is not an access token" do
    refresh_token = Flow.mint(User.admin()).__metadata__.refresh_token

    assert_challenged(Flow.rpc("tools/list", %{}, refresh_token), true)
  end

  test "an expired token is rejected" do
    assert_challenged(Flow.rpc("tools/list", %{}, token_for(User.admin(), expires_in: -1)), true)
  end

  test "a revoked token is rejected" do
    minted = Flow.mint(User.admin())
    {:ok, _revoked} = AccessToken.revoke(minted, actor: ServerActor.new())

    assert_challenged(Flow.rpc("tools/list", %{}, minted.__metadata__.token), true)
  end

  test "a token whose user no longer loads is rejected" do
    user = %User{id: User.unloadable_id(), company_id: Ash.UUID.generate()}

    assert_challenged(Flow.rpc("tools/list", %{}, token_for(user)), true)
  end

  test "a loader answering {:ok, nil} does not authenticate" do
    user = %User{id: User.loads_as_nil_id(), company_id: Ash.UUID.generate()}

    assert_challenged(Flow.rpc("tools/list", %{}, token_for(user)), true)
  end

  test "an actor from another company does not authenticate" do
    user = %User{id: User.in_other_company_id(), company_id: Ash.UUID.generate()}

    assert_challenged(Flow.rpc("tools/list", %{}, token_for(user)), true)
  end

  test "an actor without a company key is the host's to vouch for" do
    user = %User{id: User.without_company_id(), company_id: Ash.UUID.generate()}

    assert Flow.rpc("tools/list", %{}, token_for(user)).status == 200
  end

  test "the scheme is matched case-insensitively" do
    token = token_for(User.admin())

    for scheme <- ["Bearer", "bearer", "BEARER", "bEaReR"] do
      assert list_with_header("#{scheme} #{token}").status == 200, "#{scheme} was refused"
    end
  end

  describe "an authenticated request" do
    setup do
      user = User.admin()
      minted = Flow.mint(user)

      conn =
        :post
        |> conn("/")
        |> put_req_header("authorization", "Bearer " <> minted.__metadata__.token)
        |> PlugHelpers.set_context(%{upstream: :kept, mcp_scopes: ["forged"]})
        |> Bearer.call(Bearer.init(server: Server))

      %{conn: conn, user: user, minted: minted}
    end

    test "carries the token's user as actor and its company as tenant", %{conn: conn, user: user} do
      refute conn.halted
      assert %User{id: id, company_id: company_id} = PlugHelpers.get_actor(conn)
      assert id == user.id
      assert company_id == user.company_id
      assert PlugHelpers.get_tenant(conn) == user.company_id
    end

    test "merges the host context and the token's scopes into the upstream context", %{conn: conn} do
      assert PlugHelpers.get_context(conn) == %{
               upstream: :kept,
               api?: true,
               mcp_scopes: ["mcp:read"]
             }
    end

    test "assigns the token row for host plugs", %{conn: conn, minted: minted} do
      assert conn.assigns.mcp_access_token.id == minted.id
    end
  end

  test "the token's scopes override an mcp_scopes key in the host's context" do
    conn =
      :post
      |> conn("/")
      |> put_req_header("authorization", "Bearer " <> token_for(User.admin()))
      |> Bearer.call(Bearer.init(server: ConfiguredServer))

    assert PlugHelpers.get_context(conn) == %{api?: true, mcp_scopes: ["mcp:read"]}
  end
end
