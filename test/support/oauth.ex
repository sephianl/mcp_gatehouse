defmodule McpGatehouse.Test.OAuth do
  @moduledoc "The host's OAuth domain, holding the three resources built from the library's fragments."
  use Ash.Domain

  resources do
    resource McpGatehouse.Test.Client
    resource McpGatehouse.Test.AuthorizationCode
    resource McpGatehouse.Test.AccessToken
  end
end

defmodule McpGatehouse.Test.Client do
  @moduledoc "A host client resource: the fragment over a per-process ETS table."
  use Ash.Resource,
    domain: McpGatehouse.Test.OAuth,
    data_layer: Ash.DataLayer.Ets,
    fragments: [McpGatehouse.OAuth.ClientFragment]

  ets do
    private? true
  end

  # Ash.DataLayer.Verifiers.RequirePreCheckWith: ETS cannot enforce identities; Postgres hosts do.
  @spec testing_identities() :: true
  def testing_identities, do: true
end

defmodule McpGatehouse.Test.AuthorizationCode do
  @moduledoc """
  A host authorization code resource: the fragment over a per-process ETS table,
  plus `:expire`, which only tests need, to age a code past its lifetime.
  """
  use Ash.Resource,
    domain: McpGatehouse.Test.OAuth,
    data_layer: Ash.DataLayer.Ets,
    fragments: [McpGatehouse.OAuth.AuthorizationCodeFragment]

  ets do
    private? true
  end

  actions do
    update :expire do
      require_atomic? false
      change set_attribute(:expires_at, &__MODULE__.a_minute_ago/0)
    end
  end

  # Ash.DataLayer.Verifiers.RequirePreCheckWith: ETS cannot enforce identities; Postgres hosts do.
  @spec testing_identities() :: true
  def testing_identities, do: true

  @spec a_minute_ago() :: DateTime.t()
  def a_minute_ago, do: DateTime.shift(DateTime.utc_now(), minute: -1)
end

defmodule McpGatehouse.Test.AccessToken do
  @moduledoc """
  A host access token resource: the fragment over a per-process ETS table, plus
  `:backdate`, which only tests need, to move a row's issue or revocation time
  into the past instead of waiting for it.
  """
  use Ash.Resource,
    domain: McpGatehouse.Test.OAuth,
    data_layer: Ash.DataLayer.Ets,
    fragments: [McpGatehouse.OAuth.AccessTokenFragment]

  ets do
    private? true
  end

  code_interface do
    define :backdate, args: [:seconds]
  end

  actions do
    update :backdate do
      require_atomic? false

      argument :seconds, :integer, allow_nil?: false

      argument :field, :atom,
        default: :revoked_at,
        constraints: [one_of: [:revoked_at, :created_at]]

      change fn changeset, _context ->
        field = Ash.Changeset.get_argument(changeset, :field)
        seconds = Ash.Changeset.get_argument(changeset, :seconds)

        Ash.Changeset.force_change_attribute(
          changeset,
          field,
          DateTime.shift(DateTime.utc_now(), second: -seconds)
        )
      end
    end
  end

  # Ash.DataLayer.Verifiers.RequirePreCheckWith: ETS cannot enforce identities; Postgres hosts do.
  @spec testing_identities() :: true
  def testing_identities, do: true
end
