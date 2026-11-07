defmodule McpGatehouse.Test.Catalog do
  @moduledoc """
  A host domain carrying an MCP tool, with the read-only scope policy added as a
  host would add it.
  """
  use Ash.Domain,
    extensions: [AshAi],
    fragments: [McpGatehouse.ReadOnlyScopePolicy]

  alias McpGatehouse.Intent
  alias McpGatehouse.Test.Widget
  alias McpGatehouse.ToolDocs

  resources do
    resource Widget
  end

  tools do
    tool :list_widgets, Widget, :list do
      description """
      Widgets in the catalog.

      #{ToolDocs.paging()}
      """

      argument :context, Ash.Type.String, description: Intent.description()
    end
  end
end

defmodule McpGatehouse.Test.Widget do
  @moduledoc "A tool-backed resource over a per-process ETS table, with one action of each type."
  use Ash.Resource,
    domain: McpGatehouse.Test.Catalog,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  alias McpGatehouse.ToolDocs

  ets do
    private? true
  end

  code_interface do
    define :list, action: :list
    define :create, args: [:name], action: :create
    define :rename, args: [:name], action: :rename
    define :remove, action: :remove
    define :count_widgets, action: :count_widgets
  end

  actions do
    read :list do
      primary? true
      pagination keyset?: true, required?: false, max_page_size: ToolDocs.page_cap()
    end

    create :create do
      accept [:name]
    end

    update :rename do
      accept [:name]
    end

    destroy :remove

    action :count_widgets, :integer do
      run fn _input, _context -> {:ok, 0} end
    end
  end

  policies do
    policy always() do
      authorize_if actor_present()
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :name, :string do
      allow_nil? false
      public? true
    end
  end
end
