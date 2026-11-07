defmodule McpGatehouse.Tools do
  @moduledoc """
  The MCP tools every host serves alongside its own: today only
  `report_missing_capability` (`McpGatehouse.CapabilityGap`).

  A host adds this domain to its `config :my_app, ash_domains` list, which is
  where `AshAi.Mcp.Router` looks for tools, and `:report_missing_capability` to
  the router's `tools:` allowlist. `ash_ai` checks tool names for uniqueness only
  within one domain, so a host that keeps its own tool by that name must not add
  this domain, or `tools/list` serves the name twice.

  The tool carries no `description:` of its own, so the action's is what the
  model reads.
  """
  use Ash.Domain, extensions: [AshAi], validate_config_inclusion?: false

  alias McpGatehouse.CapabilityGap
  alias McpGatehouse.Intent

  resources do
    resource CapabilityGap
  end

  tools do
    tool :report_missing_capability, CapabilityGap, :report_missing_capability do
      argument :context, Ash.Type.String, description: Intent.description()
    end
  end
end
