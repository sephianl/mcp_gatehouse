defmodule McpGatehouse.OAuth.HashedSecretsTest do
  @moduledoc """
  What reaches the data layer is the hash, and the raw secret is returned
  exactly once. A row is not a usable credential.
  """
  use ExUnit.Case, async: true

  alias McpGatehouse.OAuth.OpaqueToken
  alias McpGatehouse.OAuth.ServerActor
  alias McpGatehouse.Test.AccessToken
  alias McpGatehouse.Test.AuthorizationCode
  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.User

  defp stored(resource, id) do
    {:ok, [row]} =
      resource
      |> Ash.Query.for_read(:read)
      |> Ash.Query.filter_input(%{id: id})
      |> Ash.read(authorize?: false)

    row
  end

  test "the access token columns hold hashes, never the tokens" do
    minted = Flow.mint(User.admin())
    %{token: token, refresh_token: refresh_token} = minted.__metadata__

    row = stored(AccessToken, minted.id)

    assert row.token_hash == OpaqueToken.hash(token)
    assert row.refresh_token_hash == OpaqueToken.hash(refresh_token)
    refute Map.has_key?(row.__metadata__, :token)
  end

  test "an access token and its refresh token resolve from the values the client holds" do
    minted = Flow.mint(User.admin())

    assert {:ok, %{id: id}} =
             AccessToken.get_by_token(minted.__metadata__.token, actor: ServerActor.new())

    assert id == minted.id

    assert {:ok, %{id: ^id}} =
             AccessToken.get_by_refresh_token(minted.__metadata__.refresh_token,
               actor: ServerActor.new()
             )
  end

  test "the authorization code column holds the hash and still resolves from the raw value" do
    issued = Flow.issue_code(User.admin())

    assert issued.code_hash == OpaqueToken.hash(issued.__metadata__.code)
    assert issued.code_challenge_method == :S256
    assert_in_delta DateTime.diff(issued.expires_at, DateTime.utc_now()), 600, 5

    assert {:ok, %{id: id}} =
             AuthorizationCode.get_by_code(issued.__metadata__.code, actor: ServerActor.new())

    assert id == issued.id
  end

  test "an unknown secret finds nothing" do
    assert {:error, _not_found} =
             AccessToken.get_by_token("not-a-token", actor: ServerActor.new())

    assert {:error, _not_found} =
             AuthorizationCode.get_by_code("not-a-code", actor: ServerActor.new())
  end

  test "secrets are 32 random bytes, URL-safe" do
    secrets = for _secret <- 1..50, do: OpaqueToken.generate()

    assert length(Enum.uniq(secrets)) == 50
    assert Enum.all?(secrets, &(&1 =~ ~r/\A[A-Za-z0-9_-]{43}\z/))
  end

  test "the hash is lowercase hex SHA-256, as Postgres' encode(sha256(...), 'hex') computes it" do
    assert OpaqueToken.hash("abc") ==
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  end
end
