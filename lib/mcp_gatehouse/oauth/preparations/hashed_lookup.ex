defmodule McpGatehouse.OAuth.Preparations.HashedLookup do
  @moduledoc """
  Finds a row by the hash of the secret a caller presented.

  The secret itself is never stored, so `get_by` cannot match on it. Callers
  keep passing the raw value they were issued and the hashing stays here, in one
  place, rather than at every lookup site.
  """
  use Ash.Resource.Preparation

  alias Ash.Query
  alias McpGatehouse.OAuth.OpaqueToken

  require Query

  @impl true
  @spec prepare(Query.t(), keyword(), Ash.Resource.Preparation.Context.t()) :: Query.t()
  def prepare(query, [argument: argument, attribute: attribute], _context) do
    hashed = query |> Query.get_argument(argument) |> OpaqueToken.hash()

    Query.filter(query, ^Ash.Expr.ref(attribute) == ^hashed)
  end
end
