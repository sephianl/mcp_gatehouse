defmodule McpGatehouse.OAuth.AuthorizationCodeFragment do
  @moduledoc """
  A short-lived, single-use authorization code bound to a PKCE challenge.

  It carries the tenant forward: the company is captured from the consenting
  user here and copied onto the access token at exchange, so the tenant is
  fixed by the human who consented and never by anything the client sends.

  Only the SHA-256 of the code is stored; the raw code is returned once, as
  `issue` action metadata.

  The host owns the module, domain, data layer, table and any foreign keys on
  `user_id` and `company_id` (declare them with `define_attribute?: false`).
  Every action is authorized for `McpGatehouse.OAuth.ServerActor` only, and
  there is deliberately no primary read.
  """
  use Spark.Dsl.Fragment, of: Ash.Resource, authorizers: [Ash.Policy.Authorizer]

  alias McpGatehouse.OAuth.Changes.GenerateCode
  alias McpGatehouse.OAuth.Changes.StampOnce
  alias McpGatehouse.OAuth.Checks.ServerActor
  alias McpGatehouse.OAuth.Preparations.HashedLookup

  code_interface do
    define :issue, action: :issue
    define :get_by_code, args: [:code], action: :by_code
    define :redeem, action: :redeem
  end

  actions do
    create :issue do
      description "Issues a short-lived authorization code for a client a signed-in user has just consented to, carrying that user's tenant."

      accept [
        :client_id,
        :user_id,
        :company_id,
        :redirect_uri,
        :code_challenge,
        :code_challenge_method,
        :scopes
      ]

      metadata :code, :string, allow_nil?: false

      change GenerateCode
    end

    read :by_code do
      description "Looks a code up by the hash of its opaque value during the token exchange. Says nothing about whether it is still redeemable."

      argument :code, :string, allow_nil?: false, sensitive?: true

      get? true

      prepare {HashedLookup, argument: :code, attribute: :code_hash}
    end

    update :redeem do
      description "Spends a code, and only if it was not already spent, so replaying the same code cannot mint a second token."

      require_atomic? false

      change {StampOnce, attribute: :redeemed_at}
    end
  end

  policies do
    policy always() do
      authorize_if ServerActor
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :code_hash, :string do
      description "SHA-256 of the authorization code. The code itself is never stored."
      allow_nil? false
    end

    attribute :client_id, :string, allow_nil?: false
    attribute :user_id, :uuid, allow_nil?: false
    attribute :company_id, :uuid, allow_nil?: false
    attribute :redirect_uri, :string, allow_nil?: false
    attribute :code_challenge, :string, allow_nil?: false

    attribute :code_challenge_method, :atom do
      allow_nil? false
      default :S256
      constraints one_of: [:S256]
    end

    attribute :scopes, {:array, :string}, allow_nil?: false
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false
    attribute :redeemed_at, :utc_datetime_usec

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  identities do
    identity :unique_code_hash, [:code_hash]
  end
end
