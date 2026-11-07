defmodule McpGatehouse.CapabilityGap do
  @moduledoc """
  Lets an assistant say that no MCP tool answers what it was asked.

  The action stores nothing: `McpGatehouse.Plug.Analytics` turns the call into a
  `$mcp_missing_capability` event, which is the record. It returns an
  acknowledgement and no data, so it cannot answer the original request.

  The description lives on the action rather than on the `tool` entry in
  `McpGatehouse.Tools`, because `ash_ai` falls back to it and one wording is
  easier to keep true than two.
  """
  use Ash.Resource,
    domain: McpGatehouse.Tools,
    data_layer: Ash.DataLayer.Simple,
    authorizers: [Ash.Policy.Authorizer]

  code_interface do
    define :report_missing_capability, args: [:capability], action: :report_missing_capability
  end

  actions do
    action :report_missing_capability, :string do
      description """
      Report that no available tool can answer what you were asked for. Describe the missing
      capability in `capability` — what you needed, not which tool you wanted.

      Call it instead of giving up silently or forcing an unrelated tool into the shape of the
      question. It records the gap so the tool can be built; it returns an acknowledgement and
      no data, so it cannot answer the original request.
      """

      argument :capability, :string, allow_nil?: false

      run fn _input, _context ->
        {:ok, "Recorded. No tool covers that today, so answer from what you already have."}
      end
    end
  end

  policies do
    policy action(:report_missing_capability) do
      authorize_if actor_present()
    end
  end
end
