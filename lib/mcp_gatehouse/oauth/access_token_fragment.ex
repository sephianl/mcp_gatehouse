defmodule McpGatehouse.OAuth.AccessTokenFragment do
  @moduledoc """
  An opaque MCP access token with its tenant stamped on at mint time.

  Only the SHA-256 of each secret is stored, so the raw access and refresh
  tokens exist exactly once — in the `mint` response. They are returned as
  action metadata rather than attributes because there is no column holding
  them to read back later.

  Every refresh inserts a new row and revokes the previous one, so a row's
  `created_at` is when its refresh token was issued, and the rows sharing a
  client, user and company make up one grant (`live_in_grant`).

  The host owns the module, domain, data layer, table and any foreign keys on
  `user_id` and `company_id` (declare them with `define_attribute?: false`).
  Every action is authorized for `McpGatehouse.OAuth.ServerActor` only.
  """
  use Spark.Dsl.Fragment, of: Ash.Resource, authorizers: [Ash.Policy.Authorizer]

  alias McpGatehouse.OAuth.Changes.GenerateTokens
  alias McpGatehouse.OAuth.Changes.StampOnce
  alias McpGatehouse.OAuth.Checks.ServerActor
  alias McpGatehouse.OAuth.Preparations.HashedLookup

  code_interface do
    define :read, action: :read
    define :mint, action: :mint
    define :get_by_token, args: [:token], action: :by_token
    define :get_by_refresh_token, args: [:refresh_token], action: :by_refresh_token
    define :live_in_grant, args: [:client_id, :user_id, :company_id], action: :live_in_grant
    define :revoke, action: :revoke
  end

  actions do
    create :mint do
      description "Issues an access token and its refresh token, stamping the tenant the consenting user belongs to."

      accept [:client_id, :user_id, :company_id, :scopes]

      argument :expires_in, :integer, default: 3600

      metadata :token, :string, allow_nil?: false
      metadata :refresh_token, :string, allow_nil?: false

      change GenerateTokens
    end

    read :read do
      description "Every token row, unfiltered. Present so loads and lookups have a primary read; authenticating a request goes through `by_token`."

      primary? true
    end

    read :by_token do
      description "Looks a token up by the hash of its opaque value, to authenticate one MCP request. Says nothing about whether it is still usable."

      argument :token, :string, allow_nil?: false, sensitive?: true

      get? true

      prepare {HashedLookup, argument: :token, attribute: :token_hash}
    end

    read :by_refresh_token do
      description "Looks a token up by the hash of its refresh token, to rotate it."

      argument :refresh_token, :string, allow_nil?: false, sensitive?: true

      get? true

      prepare {HashedLookup, argument: :refresh_token, attribute: :refresh_token_hash}
    end

    read :live_in_grant do
      description "Every not-yet-revoked token of one grant — a client, a user and a company — so a replayed refresh token can revoke the whole grant."

      argument :client_id, :string, allow_nil?: false
      argument :user_id, :uuid, allow_nil?: false
      argument :company_id, :uuid, allow_nil?: false

      filter expr(
               client_id == ^arg(:client_id) and user_id == ^arg(:user_id) and
                 company_id == ^arg(:company_id) and is_nil(revoked_at)
             )
    end

    update :revoke do
      description "Revokes a token, and only if it was not already revoked, so a replayed refresh cannot rotate the same token twice."

      require_atomic? false

      change {StampOnce, attribute: :revoked_at}
    end
  end

  policies do
    policy always() do
      authorize_if ServerActor
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :token_hash, :string do
      description "SHA-256 of the access token. The token itself is never stored."
      allow_nil? false
    end

    attribute :refresh_token_hash, :string do
      description "SHA-256 of the refresh token. The token itself is never stored."
      allow_nil? false
    end

    attribute :client_id, :string, allow_nil?: false
    attribute :user_id, :uuid, allow_nil?: false
    attribute :company_id, :uuid, allow_nil?: false
    attribute :scopes, {:array, :string}, allow_nil?: false
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false
    attribute :revoked_at, :utc_datetime_usec

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  identities do
    identity :unique_token_hash, [:token_hash]
    identity :unique_refresh_token_hash, [:refresh_token_hash]
  end
end
