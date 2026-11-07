defmodule McpGatehouse.OAuth.ClientFragment do
  @moduledoc """
  An MCP client registered through RFC 7591 dynamic registration.

  A client is not tenant-scoped: it registers before any human has consented,
  so it belongs to nobody until a user completes the authorization code flow.
  The tenant arrives with that user and is stamped on the access token, never
  here.

  The host owns the module, domain, data layer and table:

      defmodule MyApp.Mcp.OAuth.Client do
        use Ash.Resource,
          domain: MyApp.Mcp.OAuth,
          data_layer: AshPostgres.DataLayer,
          fragments: [McpGatehouse.OAuth.ClientFragment]

        postgres do
          table "mcp_oauth_clients"
          repo MyApp.Repo
        end
      end

  Every action is authorized for `McpGatehouse.OAuth.ServerActor` only. There is
  deliberately no primary read: the only lookup is by the client id a caller
  presents.

  Registration is open to anyone, so `:register` bounds what it stores: a
  `client_name` of at most 200 characters, and the redirect URI limits of
  `McpGatehouse.OAuth.Validations.RedirectUris`. These are action validations,
  not attribute constraints, so the table's schema is unchanged.
  """
  use Spark.Dsl.Fragment, of: Ash.Resource, authorizers: [Ash.Policy.Authorizer]

  alias McpGatehouse.OAuth.Changes.GenerateClientId
  alias McpGatehouse.OAuth.Checks.ServerActor
  alias McpGatehouse.OAuth.Scopes
  alias McpGatehouse.OAuth.Validations.RedirectUris

  code_interface do
    define :register, action: :register
    define :get_by_client_id, args: [:client_id], action: :by_client_id
  end

  actions do
    create :register do
      description "Registers a public OAuth client under RFC 7591. Anyone may register, so nothing here is evidence of who the client is."

      accept [:client_name, :redirect_uris, :token_endpoint_auth_method, :scopes]

      change GenerateClientId

      validate RedirectUris
      validate string_length(:client_name, max: 200)
    end

    read :by_client_id do
      description "Looks a registered client up by the id it presents, to check its redirect URIs against the one it asked for."

      argument :client_id, :string, allow_nil?: false
      get_by :client_id
    end
  end

  policies do
    policy always() do
      authorize_if ServerActor
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :client_id, :string do
      allow_nil? false
      public? true
    end

    attribute :client_name, :string do
      public? true
    end

    attribute :redirect_uris, {:array, :string} do
      allow_nil? false
      public? true
    end

    attribute :token_endpoint_auth_method, :atom do
      allow_nil? false
      default :none
      public? true
      constraints one_of: [:none]
    end

    attribute :scopes, {:array, :string} do
      allow_nil? false
      default &Scopes.all/0
      public? true
    end

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  identities do
    identity :unique_client_id, [:client_id]
  end
end
