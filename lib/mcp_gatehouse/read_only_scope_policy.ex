defmodule McpGatehouse.ReadOnlyScopePolicy do
  @moduledoc """
  Keeps an MCP token without `mcp:write` away from create, update and destroy
  actions, in every domain it is added to.

  Add it to each domain that carries MCP tools:

      use Ash.Domain,
        extensions: [AshAi],
        fragments: [MyApp.Fragments.Tools, McpGatehouse.ReadOnlyScopePolicy]

  A domain policy only reaches resources whose own `authorizers` include
  `Ash.Policy.Authorizer`, so this fragment does nothing for a resource without
  it. Ash says so: `Ash.Policy.Authorizer.Verifiers.VerifyResources` warns at
  compile time — fatal under `--warnings-as-errors` — for every resource of a
  domain carrying domain policies that lacks the authorizer, whether or not a
  tool reaches it. Give each such resource the authorizer and policies scoped to
  the action types it serves:

      use Ash.Resource, authorizers: [Ash.Policy.Authorizer]

      policies do
        policy action_type(:read) do
          authorize_if always()
        end
      end

  An action type no policy covers is then forbidden, so cover every type the
  resource's actions use. Do not take the warning's own suggestion, an unscoped
  `policy always() do authorize_if always() end`: AshCredo's
  `OverlyPermissivePolicy` check flags it.

  Generic actions are deliberately not covered: read-shaped tools such as
  `report_missing_capability` are generic actions, and forbidding them would
  break them for every token. It only ever forbids; authorizing here would let a
  read-only token through actions no resource policy grants.

  It cannot hide a tool from `tools/list` — `ash_ai`'s pre-check runs without the
  request context — it only refuses the call.
  """
  use Spark.Dsl.Fragment, of: Ash.Domain, extensions: [Ash.Policy.Authorizer]

  alias McpGatehouse.Checks.McpTokenLacksWriteScope

  policies do
    policy [McpTokenLacksWriteScope, action_type([:create, :update, :destroy])] do
      forbid_if always()
    end
  end
end
