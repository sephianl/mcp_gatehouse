defmodule McpGatehouse.OAuth.ServerActorTest do
  @moduledoc """
  Every action on the three OAuth resources is authorized for
  `McpGatehouse.OAuth.ServerActor` alone. A host user — even one whose token
  row it is — and a call without an actor can neither write a row nor read one
  back.
  """
  use ExUnit.Case, async: true

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Ash.Error.Query.NotFound
  alias McpGatehouse.OAuth.ServerActor
  alias McpGatehouse.Test.AccessToken
  alias McpGatehouse.Test.AuthorizationCode
  alias McpGatehouse.Test.Client
  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.User

  setup do
    %{user: User.admin()}
  end

  test "only the server actor registers or finds a client", %{user: user} do
    attrs = %{redirect_uris: ["https://claude.ai/cb"]}

    assert {:error, %Forbidden{}} = Client.register(attrs, actor: user)
    assert {:error, %Forbidden{}} = Client.register(attrs)

    {:ok, %{client_id: client_id}} = Client.register(attrs, actor: ServerActor.new())

    assert {:error, %Invalid{errors: [%NotFound{}]}} =
             Client.get_by_client_id(client_id, actor: user)

    assert {:error, %Invalid{errors: [%NotFound{}]}} = Client.get_by_client_id(client_id)

    assert {:ok, %{client_id: ^client_id}} =
             Client.get_by_client_id(client_id, actor: ServerActor.new())
  end

  test "only the server actor issues, finds or redeems a code", %{user: user} do
    assert {:error, %Forbidden{}} = AuthorizationCode.issue(Flow.code_attrs(user), actor: user)

    issued = Flow.issue_code(user)
    code = issued.__metadata__.code

    assert {:error, %Invalid{errors: [%NotFound{}]}} =
             AuthorizationCode.get_by_code(code, actor: user)

    assert {:error, %Invalid{errors: [%NotFound{}]}} = AuthorizationCode.get_by_code(code)
    assert {:error, %Forbidden{}} = AuthorizationCode.redeem(issued, actor: user)
    assert {:ok, %{id: id}} = AuthorizationCode.get_by_code(code, actor: ServerActor.new())
    assert id == issued.id
  end

  test "only the server actor mints, reads, finds or revokes a token", %{user: user} do
    assert {:error, %Forbidden{}} =
             AccessToken.mint(
               %{client_id: "c", user_id: user.id, company_id: user.company_id, scopes: []},
               actor: user
             )

    minted = Flow.mint(user)

    assert {:ok, []} = AccessToken.read(actor: user)
    assert {:ok, []} = AccessToken.read()

    assert {:error, %Invalid{errors: [%NotFound{}]}} =
             AccessToken.get_by_token(minted.__metadata__.token, actor: user)

    assert {:error, %Forbidden{}} = AccessToken.revoke(minted, actor: user)
    assert {:ok, [%{id: id}]} = AccessToken.read(actor: ServerActor.new())
    assert id == minted.id
  end
end
