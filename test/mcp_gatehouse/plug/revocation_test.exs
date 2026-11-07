defmodule McpGatehouse.Plug.RevocationTest do
  @moduledoc """
  RFC 7009 revocation: always a 200, and only the client a grant was issued to
  can revoke it.
  """
  use ExUnit.Case, async: true

  alias McpGatehouse.OAuth.ServerActor
  alias McpGatehouse.Test.AccessToken
  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.User

  setup do
    Flow.connect(User.admin())
  end

  test "another client cannot revoke a grant it does not own", %{tokens: tokens} do
    %{"client_id" => other} = Flow.register()

    assert Flow.revoke(%{"token" => tokens["access_token"], "client_id" => other}).status == 200
    assert Flow.authenticates?(tokens["access_token"])
  end

  test "a request with no client_id revokes nothing", %{tokens: tokens} do
    assert Flow.revoke(%{"token" => tokens["access_token"]}).status == 200
    assert Flow.authenticates?(tokens["access_token"])
  end

  test "the owning client revokes its own grant", %{client_id: client_id, tokens: tokens} do
    conn = Flow.revoke(%{"token" => tokens["access_token"], "client_id" => client_id})

    assert conn.status == 200
    assert conn.resp_body == ""
    refute Flow.authenticates?(tokens["access_token"])

    {:ok, revoked} = AccessToken.get_by_token(tokens["access_token"], actor: ServerActor.new())
    assert revoked.revoked_at
  end

  test "the owning client can revoke by refresh token", %{client_id: client_id, tokens: tokens} do
    assert Flow.revoke(%{"token" => tokens["refresh_token"], "client_id" => client_id}).status ==
             200

    refute Flow.authenticates?(tokens["access_token"])
    assert Flow.refresh(client_id, tokens["refresh_token"]).status == 400
  end

  test "revoking twice still answers 200", %{client_id: client_id, tokens: tokens} do
    params = %{"token" => tokens["access_token"], "client_id" => client_id}

    assert Flow.revoke(params).status == 200
    assert Flow.revoke(params).status == 200
  end

  test "an unknown or missing token is still answered with 200", %{client_id: client_id} do
    assert Flow.revoke(%{"token" => "never-issued", "client_id" => client_id}).status == 200
    assert Flow.revoke(%{"token" => "never-issued"}).status == 200
    assert Flow.revoke(%{}).status == 200
  end

  test "the response forbids storage", %{client_id: client_id} do
    conn = Flow.revoke(%{"token" => "never-issued", "client_id" => client_id})

    assert Plug.Conn.get_resp_header(conn, "cache-control") == ["no-store"]
  end
end
