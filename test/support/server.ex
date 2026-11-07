defmodule McpGatehouse.Test.Server do
  @moduledoc """
  The host's `McpGatehouse.Server`, implementing the optional `context/1` and
  `trusted_proxies/0` and leaving the rest to their defaults.

  `capture_event/4` sends the event to the calling process: under `Plug.Test` a
  `before_send` hook runs in the test process, so the test receives it.
  """
  @behaviour McpGatehouse.Server

  alias McpGatehouse.Test.User

  @impl true
  def otp_app, do: :mcp_gatehouse

  @impl true
  def server_name, do: "Test MCP"

  @impl true
  def endpoint, do: McpGatehouse.Test.Endpoint

  @impl true
  def client_resource, do: McpGatehouse.Test.Client

  @impl true
  def authorization_code_resource, do: McpGatehouse.Test.AuthorizationCode

  @impl true
  def access_token_resource, do: McpGatehouse.Test.AccessToken

  @impl true
  def load_user(user_id, company_id), do: User.load(user_id, company_id)

  @impl true
  def consent_identity(%User{role: :admin, id: id, company_id: company_id}), do: {:ok, id, company_id}

  def consent_identity(_user), do: :error

  @impl true
  def capture_event(event, distinct_id, company_id, properties) do
    send(self(), {:captured, event, distinct_id, company_id, properties})
    :ok
  end

  @impl true
  def context(_token), do: %{api?: true}

  @impl true
  def trusted_proxies, do: ["35.191.0.0/16"]
end

defmodule McpGatehouse.Test.MinimalServer do
  @moduledoc "A host server implementing only the required callbacks, so every default applies."
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
  defdelegate access_token_resource, to: Server
  @impl true
  defdelegate load_user(user_id, company_id), to: Server
  @impl true
  defdelegate consent_identity(user), to: Server
  @impl true
  defdelegate capture_event(event, distinct_id, company_id, properties), to: Server
end

defmodule McpGatehouse.Test.UnconfiguredServer do
  @moduledoc "A host server whose OTP app has no `:filtered_parameters` configured."
  @behaviour McpGatehouse.Server

  alias McpGatehouse.Test.Server

  @impl true
  def otp_app, do: :mcp_gatehouse_unconfigured
  @impl true
  defdelegate server_name, to: Server
  @impl true
  defdelegate endpoint, to: Server
  @impl true
  defdelegate client_resource, to: Server
  @impl true
  defdelegate authorization_code_resource, to: Server
  @impl true
  defdelegate access_token_resource, to: Server
  @impl true
  defdelegate load_user(user_id, company_id), to: Server
  @impl true
  defdelegate consent_identity(user), to: Server
  @impl true
  defdelegate capture_event(event, distinct_id, company_id, properties), to: Server
end

defmodule McpGatehouse.Test.ConfiguredServer do
  @moduledoc "A host server answering every optional callback with a non-default value."
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
  defdelegate access_token_resource, to: Server
  @impl true
  defdelegate load_user(user_id, company_id), to: Server
  @impl true
  defdelegate consent_identity(user), to: Server
  @impl true
  defdelegate capture_event(event, distinct_id, company_id, properties), to: Server
  @impl true
  defdelegate context(token), to: Server
  @impl true
  def filtered_parameters, do: ["fuel", "apiKey"]
  @impl true
  def analytics_payloads, do: :full
  @impl true
  defdelegate trusted_proxies, to: Server
  @impl true
  def refresh_idle_ttl, do: 60
end

defmodule McpGatehouse.Test.EnvelopeServer do
  @moduledoc "A host server sending analytics envelopes only."
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
  defdelegate access_token_resource, to: Server
  @impl true
  defdelegate load_user(user_id, company_id), to: Server
  @impl true
  defdelegate consent_identity(user), to: Server
  @impl true
  defdelegate capture_event(event, distinct_id, company_id, properties), to: Server
  @impl true
  def analytics_payloads, do: :envelope
end

defmodule McpGatehouse.Test.RaisingServer do
  @moduledoc "A host server whose analytics backend fails."
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
  defdelegate access_token_resource, to: Server
  @impl true
  defdelegate load_user(user_id, company_id), to: Server
  @impl true
  defdelegate consent_identity(user), to: Server
  @impl true
  def capture_event(_event, _distinct_id, _company_id, _properties), do: raise("analytics backend is down")
end

defmodule McpGatehouse.Test.LazyServer do
  @moduledoc "A host server that only one test touches, so that test can unload it first."
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
  defdelegate access_token_resource, to: Server
  @impl true
  defdelegate load_user(user_id, company_id), to: Server
  @impl true
  defdelegate consent_identity(user), to: Server
  @impl true
  defdelegate capture_event(event, distinct_id, company_id, properties), to: Server
  @impl true
  def refresh_idle_ttl, do: 42
end
