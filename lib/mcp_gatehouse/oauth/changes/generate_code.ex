defmodule McpGatehouse.OAuth.Changes.GenerateCode do
  @moduledoc """
  Assigns an authorization code the hash of its opaque value and its expiry, and
  returns the raw code as action metadata.

  Ten minutes is the RFC 6749 ceiling: the code only has to survive one redirect
  back to the client. Only the hash is persisted, so this is the one point the
  raw code is readable.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias McpGatehouse.OAuth.OpaqueToken

  @lifetime_minutes 10

  @impl true
  @spec change(Changeset.t(), keyword(), Ash.Resource.Change.Context.t()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    code = OpaqueToken.generate()

    changeset
    |> Changeset.force_change_attribute(:code_hash, OpaqueToken.hash(code))
    |> Changeset.force_change_attribute(
      :expires_at,
      DateTime.shift(DateTime.utc_now(), minute: @lifetime_minutes)
    )
    |> Changeset.after_action(&issued(&1, &2, code))
  end

  defp issued(_changeset, issued, code), do: {:ok, Ash.Resource.put_metadata(issued, :code, code)}
end
