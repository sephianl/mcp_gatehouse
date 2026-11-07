defmodule McpGatehouse.OAuth.Changes.GenerateTokens do
  @moduledoc """
  Assigns a freshly minted row the hashes of its access and refresh tokens, the
  moment the access token stops working, and returns the raw secrets as action
  metadata.

  Both values are generated here rather than accepted, so nothing a client sends
  can decide either. Only their hashes are persisted, which makes this the one
  and only point the raw tokens are readable.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias McpGatehouse.OAuth.OpaqueToken

  @impl true
  @spec change(Changeset.t(), keyword(), Ash.Resource.Change.Context.t()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    token = OpaqueToken.generate()
    refresh_token = OpaqueToken.generate()
    expires_in = Changeset.get_argument(changeset, :expires_in)

    changeset
    |> Changeset.force_change_attribute(:token_hash, OpaqueToken.hash(token))
    |> Changeset.force_change_attribute(:refresh_token_hash, OpaqueToken.hash(refresh_token))
    |> Changeset.force_change_attribute(
      :expires_at,
      DateTime.shift(DateTime.utc_now(), second: expires_in)
    )
    |> Changeset.after_action(&issued(&1, &2, token, refresh_token))
  end

  defp issued(_changeset, minted, token, refresh_token) do
    {:ok,
     minted
     |> Ash.Resource.put_metadata(:token, token)
     |> Ash.Resource.put_metadata(:refresh_token, refresh_token)}
  end
end
