defmodule McpGatehouse.Checks.McpTokenLacksWriteScope do
  @moduledoc """
  True when the request came in on an MCP token that was not granted `mcp:write`.

  `McpGatehouse.Plug.Bearer` stamps the token's scopes into the Ash context as
  `mcp_scopes`; a request without that key did not come through MCP and never
  matches.
  """
  use Ash.Policy.SimpleCheck

  @write "mcp:write"

  @impl true
  @spec describe(keyword()) :: String.t()
  def describe(_options), do: "request uses an MCP token without the #{@write} scope"

  @impl true
  @spec match?(term(), map(), keyword()) :: boolean()
  def match?(_actor, %{subject: %{context: %{mcp_scopes: scopes}}}, _options) when is_list(scopes) do
    @write not in scopes
  end

  def match?(_actor, _context, _options), do: false
end
