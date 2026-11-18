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
  alias Ash.Expr

  require Expr

  @impl true
  @spec change(Changeset.t(), keyword(), Ash.Resource.Change.Context.t()) :: Changeset.t()
  def change(changeset, [attribute: attribute], _context) do
    changeset
    |> only_when_unset(attribute)
    |> Changeset.force_change_attribute(attribute, DateTime.utc_now())
  end

  @impl true
  def atomic(changeset, [attribute: attribute], _context),
    do: {:atomic, only_when_unset(changeset, attribute), %{attribute => Expr.expr(now())}}

  defp only_when_unset(changeset, attribute), do: Changeset.filter(changeset, Expr.expr(is_nil(^Expr.ref(attribute))))
end
