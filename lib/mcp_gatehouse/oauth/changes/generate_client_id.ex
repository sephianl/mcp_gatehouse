defmodule McpGatehouse.OAuth.Changes.GenerateClientId do
  @moduledoc """
  Assigns a registering client the identifier it will present from then on.

  The server picks it rather than the client, so one registration cannot claim
  the identity of another.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias McpGatehouse.OAuth.OpaqueToken

  @impl true
  @spec change(Changeset.t(), keyword(), Ash.Resource.Change.Context.t()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    Changeset.force_change_attribute(changeset, :client_id, OpaqueToken.generate())
  end
end
