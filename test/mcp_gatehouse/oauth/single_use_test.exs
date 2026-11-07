defmodule McpGatehouse.OAuth.SingleUseTest do
  @moduledoc """
  Single use has to hold at the data layer, not in the token endpoint's
  read-then-write.

  Redeeming from a struct loaded before someone else redeemed it is the same
  shape as two concurrent exchanges of one code: both see `redeemed_at: nil`.
  With an unconditional UPDATE both succeed and both mint a token. The truly
  concurrent race needs Postgres and runs in the host suites.
  """
  use ExUnit.Case, async: true

  alias Ash.Error.Changes.StaleRecord
  alias Ash.Error.Invalid
  alias McpGatehouse.OAuth.ServerActor
  alias McpGatehouse.Test.AccessToken
  alias McpGatehouse.Test.AuthorizationCode
  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.User

  test "a code cannot be redeemed twice from a stale read" do
    code = Flow.issue_code(User.admin())

    assert {:ok, _redeemed} = AuthorizationCode.redeem(code, actor: ServerActor.new())

    assert {:error, %Invalid{errors: [%StaleRecord{}]}} =
             AuthorizationCode.redeem(code, actor: ServerActor.new())
  end

  test "a token cannot be revoked twice from a stale read" do
    token = Flow.mint(User.admin())

    assert {:ok, _revoked} = AccessToken.revoke(token, actor: ServerActor.new())

    assert {:error, %Invalid{errors: [%StaleRecord{}]}} =
             AccessToken.revoke(token, actor: ServerActor.new())
  end

  test "a grant's live tokens are the unrevoked ones of its client, user and company" do
    user = User.admin()
    live = Flow.mint(user, client_id: "grant")
    revoked = Flow.mint(user, client_id: "grant")
    _other_client = Flow.mint(user, client_id: "other")
    _other_user = Flow.mint(User.admin(), client_id: "grant", company_id: user.company_id)
    _other_company = Flow.mint(user, client_id: "grant", company_id: Ash.UUID.generate())
    {:ok, _revoked} = AccessToken.revoke(revoked, actor: ServerActor.new())

    {:ok, found} =
      AccessToken.live_in_grant("grant", user.id, user.company_id, actor: ServerActor.new())

    assert Enum.map(found, & &1.id) == [live.id]
  end
end
