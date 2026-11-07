defmodule McpGatehouse.OAuth.Changes.StampOnce do
  @moduledoc """
  Stamps a timestamp attribute with the current time, and only if it is still
  unset.

  The filter is what makes the action single-use. Two concurrent requests can
  both read an unstamped row, but only one UPDATE matches it, so the loser
  fails rather than redeeming the same code or rotating the same token twice.

  That guarantee is the data layer's filtered UPDATE: it holds on Postgres, not
  on `Ash.DataLayer.Ets`, which reads, checks and writes without a lock.
  """

  use Ash.Resource.Change

  alias Ash.Changeset

  require Ash.Expr

  @impl true
  @spec change(Changeset.t(), keyword(), Ash.Resource.Change.Context.t()) :: Changeset.t()
  def change(changeset, [attribute: attribute], _context) do
    changeset
    |> Changeset.filter(Ash.Expr.expr(is_nil(^Ash.Expr.ref(attribute))))
    |> Changeset.force_change_attribute(attribute, DateTime.utc_now())
  end
end
