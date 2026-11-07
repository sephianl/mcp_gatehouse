defmodule McpGatehouse.OAuth.Checks.ServerActor do
  @moduledoc """
  True when the actor is `McpGatehouse.OAuth.ServerActor`.

  The OAuth resources authorize nothing else, and a host grants the user lookup
  behind a token with it:

      bypass McpGatehouse.OAuth.Checks.ServerActor do
        authorize_if action(:get_by_id)
      end
  """
  use Ash.Policy.SimpleCheck

  alias McpGatehouse.OAuth.ServerActor

  @impl true
  @spec describe(keyword()) :: String.t()
  def describe(_options), do: "actor is the MCP OAuth server"

  @impl true
  @spec match?(term(), map(), keyword()) :: boolean()
  def match?(%ServerActor{}, _context, _options), do: true
  def match?(_actor, _context, _options), do: false
end
