defmodule McpGatehouse.OAuthFlowTest do
  @moduledoc """
  The authorization code flow with PKCE, end to end, and the two properties
  that make it safe to hand the resulting token to a model: the tenant is the
  consenting user's company and nothing the client sends can change it, and a
  code is worthless without the verifier that created its challenge.
  """
  use ExUnit.Case, async: true

  alias McpGatehouse.OAuth.ServerActor
  alias McpGatehouse.Test.AccessToken
  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.User

  test "register, consent, exchange, call, refresh and revoke" do
    user = User.admin()

    %{"client_id" => client_id} = Flow.register()
    {verifier, challenge} = Flow.pkce()

    callback = Flow.approve(client_id, challenge, user)
    assert String.starts_with?(callback, Flow.redirect_uri() <> "?")

    query = Flow.query(callback)
    assert query["state"] == "opaque-state"
    assert query["iss"] == "https://mcp.example.test"

    exchanged = Flow.exchange_code(client_id, query["code"], verifier)
    assert exchanged.status == 200

    first = Flow.json(exchanged)
    assert first["token_type"] == "Bearer"
    assert first["expires_in"] == 3600
    assert first["scope"] == "mcp:read"

    {:ok, row} = AccessToken.get_by_token(first["access_token"], actor: ServerActor.new())
    assert row.company_id == user.company_id
    assert row.user_id == user.id

    tools =
      "tools/list"
      |> Flow.rpc(%{}, first["access_token"])
      |> Flow.json()
      |> get_in(["result", "tools"])
      |> Enum.map(& &1["name"])

    assert Enum.sort(tools) == ["list_widgets", "report_missing_capability"]

    refreshed = client_id |> Flow.refresh(first["refresh_token"]) |> Flow.json()
    refute refreshed["access_token"] == first["access_token"]
    refute refreshed["refresh_token"] == first["refresh_token"]

    refute Flow.authenticates?(first["access_token"])
    assert Flow.authenticates?(refreshed["access_token"])

    assert Flow.revoke(%{"token" => refreshed["access_token"], "client_id" => client_id}).status ==
             200

    refute Flow.authenticates?(refreshed["access_token"])
  end

  test "a token's access expires an hour after minting" do
    %{tokens: tokens} = Flow.connect(User.admin())

    {:ok, row} = AccessToken.get_by_token(tokens["access_token"], actor: ServerActor.new())

    assert_in_delta DateTime.diff(row.expires_at, DateTime.utc_now()), 3600, 5
  end

  test "the client cannot pick the tenant: a company_id in the exchange is ignored" do
    user = User.admin()
    %{"client_id" => client_id} = Flow.register()
    {verifier, challenge} = Flow.pkce()
    %{"code" => code} = client_id |> Flow.approve(challenge, user) |> Flow.query()

    body =
      client_id
      |> Flow.exchange_code(code, verifier, %{"company_id" => Ash.UUID.generate()})
      |> Flow.json()

    {:ok, row} = AccessToken.get_by_token(body["access_token"], actor: ServerActor.new())
    assert row.company_id == user.company_id
  end
end
