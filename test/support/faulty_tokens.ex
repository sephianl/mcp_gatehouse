defmodule McpGatehouse.Test.StaleGrantTokens do
  @moduledoc """
  The host's access token resource, except that `live_in_grant/4` revokes the
  first live row itself before handing back all of them, so the token endpoint
  revokes a row that someone else revoked after the read, as a concurrent replay
  would on Postgres.
  """

  alias McpGatehouse.Test.AccessToken

  @spec get_by_refresh_token(String.t(), keyword()) :: {:ok, struct()} | {:error, term()}
  defdelegate get_by_refresh_token(refresh_token, opts), to: AccessToken

  @spec mint(map(), keyword()) :: {:ok, struct()} | {:error, term()}
  defdelegate mint(attrs, opts), to: AccessToken

  @spec revoke(struct(), keyword()) :: {:ok, struct()} | {:error, term()}
  defdelegate revoke(token, opts), to: AccessToken

  @spec live_in_grant(String.t(), String.t(), String.t(), keyword()) ::
          {:ok, [struct()]} | {:error, term()}
  def live_in_grant(client_id, user_id, company_id, opts) do
    with {:ok, [first | _rest] = live} <-
           AccessToken.live_in_grant(client_id, user_id, company_id, opts),
         {:ok, _revoked} <- AccessToken.revoke(first, opts) do
      {:ok, live}
    end
  end
end

defmodule McpGatehouse.Test.FailingRevokeTokens do
  @moduledoc """
  The host's access token resource, except that `revoke/2` fails with a
  validation error that is not a stale record, as a data layer refusing the
  write would.
  """

  alias Ash.Error.Changes.InvalidAttribute
  alias McpGatehouse.Test.AccessToken

  @spec get_by_refresh_token(String.t(), keyword()) :: {:ok, struct()} | {:error, term()}
  defdelegate get_by_refresh_token(refresh_token, opts), to: AccessToken

  @spec live_in_grant(String.t(), String.t(), String.t(), keyword()) ::
          {:ok, [struct()]} | {:error, term()}
  defdelegate live_in_grant(client_id, user_id, company_id, opts), to: AccessToken

  @spec revoke(struct(), keyword()) :: {:error, term()}
  def revoke(_token, _opts) do
    {:error, Ash.Error.to_error_class(InvalidAttribute.exception(field: :revoked_at, message: "write refused"))}
  end
end

defmodule McpGatehouse.Test.StaleGrantServer do
  @moduledoc "A host server whose grant read races a concurrent revocation."
  @behaviour McpGatehouse.Server

  alias McpGatehouse.Test.Server

  @impl true
  defdelegate otp_app, to: Server
  @impl true
  defdelegate server_name, to: Server
  @impl true
  defdelegate endpoint, to: Server
  @impl true
  defdelegate client_resource, to: Server
  @impl true
  defdelegate authorization_code_resource, to: Server
  @impl true
  def access_token_resource, do: McpGatehouse.Test.StaleGrantTokens
  @impl true
  defdelegate load_user(user_id, company_id), to: Server
  @impl true
  defdelegate consent_identity(user), to: Server
  @impl true
  defdelegate capture_event(event, distinct_id, company_id, properties), to: Server
end

defmodule McpGatehouse.Test.FailingRevokeServer do
  @moduledoc "A host server whose access token rows cannot be revoked."
  @behaviour McpGatehouse.Server

  alias McpGatehouse.Test.Server

  @impl true
  defdelegate otp_app, to: Server
  @impl true
  defdelegate server_name, to: Server
  @impl true
  defdelegate endpoint, to: Server
  @impl true
  defdelegate client_resource, to: Server
  @impl true
  defdelegate authorization_code_resource, to: Server
  @impl true
  def access_token_resource, do: McpGatehouse.Test.FailingRevokeTokens
  @impl true
  defdelegate load_user(user_id, company_id), to: Server
  @impl true
  defdelegate consent_identity(user), to: Server
  @impl true
  defdelegate capture_event(event, distinct_id, company_id, properties), to: Server
end
