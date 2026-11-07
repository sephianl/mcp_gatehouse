defmodule McpGatehouse.Plug.TokenTest do
  @moduledoc """
  The token endpoint's refusals. A code is spent before a token is minted and
  only with the verifier, client and redirect it was issued for; a refresh token
  rotates once, a revoked one presented again revokes the whole grant, an idle
  one stops working, and a grant whose user no longer loads stops rotating.
  Every refusal is an OAuth error, never a crash; a grant the endpoint failed to
  revoke is a logged 500.

  Single use under real concurrency is a property of the host's Postgres
  filtered UPDATE, so the concurrent-exchange race is a host-suite test; the
  per-process ETS tables here only prove the sequential replay.
  """
  use ExUnit.Case, async: true

  alias McpGatehouse.OAuth.ServerActor
  alias McpGatehouse.Plug.Token
  alias McpGatehouse.Test.AccessToken
  alias McpGatehouse.Test.AuthorizationCode
  alias McpGatehouse.Test.ConfiguredServer
  alias McpGatehouse.Test.FailingRevokeServer
  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.StaleGrantServer
  alias McpGatehouse.Test.User

  defp authorized(user \\ User.admin()) do
    %{"client_id" => client_id} = Flow.register()
    {verifier, challenge} = Flow.pkce()
    %{"code" => code} = client_id |> Flow.approve(challenge, user) |> Flow.query()

    %{client_id: client_id, code: code, verifier: verifier}
  end

  defp assert_invalid_grant(conn) do
    assert conn.status == 400

    assert Flow.json(conn) == %{
             "error" => "invalid_grant",
             "error_description" => "the authorization code or verifier is invalid"
           }
  end

  defp works?(access_token), do: Flow.rpc("tools/list", %{}, access_token).status == 200

  defp row_for(refresh_token) do
    {:ok, row} = AccessToken.get_by_refresh_token(refresh_token, actor: ServerActor.new())
    row
  end

  defp backdate(refresh_token, seconds, field) do
    {:ok, _backdated} =
      refresh_token
      |> row_for()
      |> AccessToken.backdate(seconds, %{field: field}, actor: ServerActor.new())
  end

  defp second_consent(client_id, user) do
    {verifier, challenge} = Flow.pkce()
    %{"code" => code} = client_id |> Flow.approve(challenge, user) |> Flow.query()

    client_id |> Flow.exchange_code(code, verifier) |> Flow.json()
  end

  describe "authorization code grant" do
    test "a code is single use" do
      %{client_id: client_id, code: code, verifier: verifier} = authorized()

      assert Flow.exchange_code(client_id, code, verifier).status == 200
      assert_invalid_grant(Flow.exchange_code(client_id, code, verifier))
    end

    test "replaying a spent code revokes nothing" do
      %{client_id: client_id, code: code, verifier: verifier} = authorized()

      tokens = client_id |> Flow.exchange_code(code, verifier) |> Flow.json()

      assert_invalid_grant(Flow.exchange_code(client_id, code, "not-the-verifier"))
      assert_invalid_grant(Flow.exchange_code(client_id, code, verifier))
      assert works?(tokens["access_token"])
    end

    test "the wrong verifier does not exchange" do
      %{client_id: client_id, code: code} = authorized()

      assert_invalid_grant(Flow.exchange_code(client_id, code, "not-the-verifier"))
    end

    test "a missing verifier does not exchange" do
      %{client_id: client_id, code: code} = authorized()

      assert_invalid_grant(
        Flow.post_form("/mcp/oauth/token", %{
          "grant_type" => "authorization_code",
          "code" => code,
          "client_id" => client_id,
          "redirect_uri" => Flow.redirect_uri()
        })
      )
    end

    test "another client cannot exchange the code" do
      %{code: code, verifier: verifier} = authorized()
      %{"client_id" => other} = Flow.register()

      assert_invalid_grant(Flow.exchange_code(other, code, verifier))
    end

    test "a different redirect uri does not exchange" do
      %{client_id: client_id, code: code, verifier: verifier} = authorized()

      assert_invalid_grant(
        Flow.exchange_code(client_id, code, verifier, %{
          "redirect_uri" => "https://claude.ai/other"
        })
      )
    end

    test "an expired code does not exchange" do
      %{client_id: client_id, code: code, verifier: verifier} = authorized()

      {:ok, issued} = AuthorizationCode.get_by_code(code, actor: ServerActor.new())

      {:ok, _expired} =
        issued |> Ash.Changeset.for_update(:expire) |> Ash.update(actor: ServerActor.new())

      assert_invalid_grant(Flow.exchange_code(client_id, code, verifier))
    end

    test "an unknown or missing code does not exchange" do
      %{client_id: client_id, verifier: verifier} = authorized()

      assert_invalid_grant(Flow.exchange_code(client_id, "never-issued", verifier))

      assert_invalid_grant(
        Flow.post_form("/mcp/oauth/token", %{
          "grant_type" => "authorization_code",
          "client_id" => client_id
        })
      )
    end

    test "an exchange accepts a JSON body too" do
      %{client_id: client_id, code: code, verifier: verifier} = authorized()

      conn =
        Flow.post_json("/mcp/oauth/token", %{
          "grant_type" => "authorization_code",
          "code" => code,
          "code_verifier" => verifier,
          "client_id" => client_id,
          "redirect_uri" => Flow.redirect_uri()
        })

      assert conn.status == 200
    end
  end

  describe "refresh token grant" do
    setup do
      user = User.admin()

      Map.put(Flow.connect(user), :user, user)
    end

    test "rotates once: the rotated token cannot be replayed", %{
      client_id: client_id,
      tokens: tokens
    } do
      rotated = client_id |> Flow.refresh(tokens["refresh_token"]) |> Flow.json()

      refute rotated["refresh_token"] == tokens["refresh_token"]
      assert rotated["expires_in"] == 3600
      assert rotated["scope"] == "mcp:read"

      assert_invalid_grant(Flow.refresh(client_id, tokens["refresh_token"]))
    end

    test "a replay within the grace period is refused but leaves the successor alone", %{
      client_id: client_id,
      tokens: tokens
    } do
      rotated = client_id |> Flow.refresh(tokens["refresh_token"]) |> Flow.json()

      assert_invalid_grant(Flow.refresh(client_id, tokens["refresh_token"]))

      assert works?(rotated["access_token"])
      assert Flow.refresh(client_id, rotated["refresh_token"]).status == 200
    end

    test "a replay after the grace period revokes the whole grant", %{
      client_id: client_id,
      tokens: tokens,
      user: user
    } do
      rotated = client_id |> Flow.refresh(tokens["refresh_token"]) |> Flow.json()
      sibling = second_consent(client_id, user)
      assert works?(sibling["access_token"])
      backdate(tokens["refresh_token"], 10, :revoked_at)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert_invalid_grant(Flow.refresh(client_id, tokens["refresh_token"]))
        end)

      assert log =~ "revoked MCP refresh token presented again; revoked 2 live token(s)"
      refute works?(rotated["access_token"])
      assert_invalid_grant(Flow.refresh(client_id, rotated["refresh_token"]))
      assert row_for(rotated["refresh_token"]).revoked_at
      refute works?(sibling["access_token"])
      assert_invalid_grant(Flow.refresh(client_id, sibling["refresh_token"]))
      assert row_for(sibling["refresh_token"]).revoked_at
    end

    test "a grant row revoked by someone else after the grant was read counts as revoked", %{
      client_id: client_id,
      tokens: tokens,
      user: user
    } do
      rotated = client_id |> Flow.refresh(tokens["refresh_token"]) |> Flow.json()
      sibling = second_consent(client_id, user)
      backdate(tokens["refresh_token"], 10, :revoked_at)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert_invalid_grant(Flow.refresh_through(StaleGrantServer, client_id, tokens["refresh_token"]))
        end)

      assert log =~ "revoked 2 live token(s)"

      for successor <- [rotated, sibling] do
        refute works?(successor["access_token"])
        assert row_for(successor["refresh_token"]).revoked_at
      end
    end

    test "a grant that cannot be revoked is a server_error, logged with the grant", %{
      client_id: client_id,
      tokens: tokens,
      user: user
    } do
      rotated = client_id |> Flow.refresh(tokens["refresh_token"]) |> Flow.json()
      backdate(tokens["refresh_token"], 10, :revoked_at)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          conn = Flow.refresh_through(FailingRevokeServer, client_id, tokens["refresh_token"])

          assert conn.status == 500
          assert Flow.json(conn) == %{"error" => "server_error"}
        end)

      assert log =~ "[error]"
      assert log =~ "could not be revoked"
      assert log =~ "write refused"

      for id <- [client_id, user.id, user.company_id] do
        assert log =~ id
      end

      assert works?(rotated["access_token"])
    end

    test "a replay by another client revokes nothing", %{client_id: client_id, tokens: tokens} do
      rotated = client_id |> Flow.refresh(tokens["refresh_token"]) |> Flow.json()

      backdate(tokens["refresh_token"], 10, :revoked_at)

      %{"client_id" => other} = Flow.register()

      assert_invalid_grant(Flow.refresh(other, tokens["refresh_token"]))
      assert works?(rotated["access_token"])
    end

    test "the grant's other clients and users are untouched by a replay", %{
      client_id: client_id,
      tokens: tokens
    } do
      bystander = Flow.connect(User.admin())
      rotated = client_id |> Flow.refresh(tokens["refresh_token"]) |> Flow.json()

      backdate(tokens["refresh_token"], 10, :revoked_at)

      ExUnit.CaptureLog.capture_log(fn -> Flow.refresh(client_id, tokens["refresh_token"]) end)

      refute works?(rotated["access_token"])
      assert works?(bystander.tokens["access_token"])
    end

    test "a refresh token idle past the server's TTL no longer rotates", %{
      client_id: client_id,
      tokens: tokens
    } do
      backdate(tokens["refresh_token"], 91 * 24 * 3600, :created_at)

      assert_invalid_grant(Flow.refresh(client_id, tokens["refresh_token"]))
    end

    test "a refresh token used within the TTL rotates", %{client_id: client_id, tokens: tokens} do
      backdate(tokens["refresh_token"], 89 * 24 * 3600, :created_at)

      assert Flow.refresh(client_id, tokens["refresh_token"]).status == 200
    end

    test "the idle TTL is the host's own refresh_idle_ttl/0", %{
      client_id: client_id,
      tokens: tokens,
      user: user
    } do
      backdate(tokens["refresh_token"], 120, :created_at)

      assert_invalid_grant(Flow.refresh_through(ConfiguredServer, client_id, tokens["refresh_token"]))

      recent = second_consent(client_id, user)
      backdate(recent["refresh_token"], 30, :created_at)

      assert Flow.refresh_through(ConfiguredServer, client_id, recent["refresh_token"]).status ==
               200
    end

    test "a grant whose user no longer loads does not rotate" do
      for user_id <- [User.unloadable_id(), User.loads_as_nil_id(), User.in_other_company_id()] do
        user = %User{id: user_id, company_id: Ash.UUID.generate()}
        %{client_id: client_id, tokens: tokens} = Flow.connect(user)

        assert_invalid_grant(Flow.refresh(client_id, tokens["refresh_token"]))
        assert is_nil(row_for(tokens["refresh_token"]).revoked_at)
      end
    end

    test "an unknown or missing refresh token is refused", %{client_id: client_id} do
      assert_invalid_grant(Flow.refresh(client_id, "never-issued"))

      assert_invalid_grant(
        Flow.post_form("/mcp/oauth/token", %{
          "grant_type" => "refresh_token",
          "client_id" => client_id
        })
      )
    end
  end

  test "an unsupported grant type is refused" do
    conn = Flow.post_form("/mcp/oauth/token", %{"grant_type" => "client_credentials"})

    assert conn.status == 400
    assert Flow.json(conn) == %{"error" => "unsupported_grant_type"}
  end

  test "credential responses forbid storage" do
    %{client_id: client_id, code: code, verifier: verifier} = authorized()

    for conn <- [
          Flow.exchange_code(client_id, code, verifier),
          Flow.exchange_code(client_id, code, verifier)
        ] do
      assert Plug.Conn.get_resp_header(conn, "cache-control") == ["no-store"]
      assert Plug.Conn.get_resp_header(conn, "pragma") == ["no-cache"]
    end
  end

  test "an endpoint without a server raises before spending the code" do
    %{client_id: client_id, code: code, verifier: verifier} = authorized()

    params = %{
      "grant_type" => "authorization_code",
      "code" => code,
      "code_verifier" => verifier,
      "client_id" => client_id,
      "redirect_uri" => Flow.redirect_uri()
    }

    assert_raise ArgumentError, ~r/McpGatehouse.Plug.Token has no MCP server/, fn ->
      :post |> Plug.Test.conn("/mcp/oauth/token", params) |> Token.call(Token.init([]))
    end

    assert Flow.exchange_code(client_id, code, verifier).status == 200
  end
end
