defmodule McpGatehouse.Intent do
  @moduledoc """
  The `context` argument every MCP tool advertises so a calling agent states why
  it is calling.

  Declared per tool rather than on the underlying actions: `ash_ai` counts
  tool-level arguments as valid input and then takes only the action's own inputs
  before running it, so this reaches the advertised schema and the analytics
  envelope without any action having to accept an argument it does not use.

      tool :list_orders, MyApp.Order, :list do
        argument :context, Ash.Type.String, description: McpGatehouse.Intent.description()
      end

  `McpGatehouse.Plug.Analytics` reports it as `$mcp_intent`.
  """

  @description "Why are you calling this tool? Briefly describe the user's goal."

  @doc """
  The prompt shown to agents for the `context` argument.
  """
  @spec description() :: String.t()
  def description, do: @description
end
