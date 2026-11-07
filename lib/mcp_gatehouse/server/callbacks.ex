defmodule McpGatehouse.Server.Callbacks do
  @moduledoc """
  Reads a host's `McpGatehouse.Server`, applying the defaults for the optional
  callbacks it leaves out, and derives what every plug needs from it.

  An optional callback counts as implemented only once the module is loaded:
  `function_exported?/3` is false for a module nothing has loaded yet, which in
  dev and test would silently swap a host's answer for the default on the first
  request of a fresh VM.

  `issuer/1` is the endpoint URL exactly, with no trailing slash or path: RFC
  8414 clients compare it character for character, and already-registered
  clients hold the value they were first given.
  """

  @default_filtered_parameters ~w(password token secret code_verifier code_challenge)
  @default_refresh_idle_ttl 90 * 24 * 3600

  @doc "The host's extra Ash context for a token, or `%{}`."
  @spec context(module(), McpGatehouse.Server.token()) :: map()
  def context(server, token), do: optional(server, :context, [token], %{})

  @doc "The parameter names analytics redacts."
  @spec filtered_parameters(module()) :: [String.t()]
  def filtered_parameters(server) do
    default =
      configured_filtered_parameters(Application.get_env(server.otp_app(), :filtered_parameters))

    optional(server, :filtered_parameters, [], default)
  end

  @doc "How much of a tool call reaches analytics."
  @spec analytics_payloads(module()) :: :envelope | :input | :full
  def analytics_payloads(server), do: optional(server, :analytics_payloads, [], :input)

  @doc "The proxies trusted to append to `X-Forwarded-For`."
  @spec trusted_proxies(module()) :: [String.t()]
  def trusted_proxies(server), do: optional(server, :trusted_proxies, [], [])

  @doc "Seconds a refresh token may sit unused."
  @spec refresh_idle_ttl(module()) :: pos_integer()
  def refresh_idle_ttl(server), do: optional(server, :refresh_idle_ttl, [], @default_refresh_idle_ttl)

  @doc "The absolute URL of `path` on the host's endpoint."
  @spec url(module(), String.t()) :: String.t()
  def url(server, path) do
    endpoint = server.endpoint()

    endpoint.url() <> endpoint.path(path)
  end

  @doc "The authorization server's issuer identifier: the endpoint URL exactly."
  @spec issuer(module()) :: String.t()
  def issuer(server), do: server.endpoint().url()

  @doc """
  Loads the actor behind a grant and checks it belongs to the grant's company.

  `{:ok, nil}` and an actor whose `:company_id` is not `company_id` are refused
  here, so a host loader that forgot its tenant cannot authenticate across
  companies.
  """
  @spec load_owner(module(), String.t(), String.t()) :: {:ok, term()} | :error
  def load_owner(server, user_id, company_id) do
    case server.load_user(user_id, company_id) do
      {:ok, actor} -> owned_by(actor, company_id)
      _not_loaded -> :error
    end
  end

  defp owned_by(nil, _company_id), do: :error
  defp owned_by(%{company_id: company_id} = actor, company_id), do: {:ok, actor}
  defp owned_by(%{company_id: _other_company}, _company_id), do: :error
  defp owned_by(actor, _company_id), do: {:ok, actor}

  defp configured_filtered_parameters(configured) when is_list(configured), do: configured
  defp configured_filtered_parameters(_unset), do: @default_filtered_parameters

  defp optional(server, name, args, default) do
    if Code.ensure_loaded?(server) and function_exported?(server, name, length(args)),
      do: apply(server, name, args),
      else: default
  end
end
