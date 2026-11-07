defmodule McpGatehouse.OAuth.Lookup do
  @moduledoc """
  Finds the OAuth rows a request presents a value for, in the host's resources
  and as `McpGatehouse.OAuth.ServerActor`.

  Each lookup answers `{:ok, row}` or `:error`, whatever the reason the row was
  not found — including a value that is not a string at all — so the caller
  decides which OAuth error a miss becomes. None of them says whether the row is
  still usable.
  """

  alias McpGatehouse.OAuth.ServerActor

  @doc "The registered client with `client_id`."
  @spec fetch_client(module(), term()) :: {:ok, struct()} | :error
  def fetch_client(server, client_id) when is_binary(client_id),
    do: found(server.client_resource().get_by_client_id(client_id, actor: ServerActor.new()))

  def fetch_client(_server, _client_id), do: :error

  @doc "The authorization code row for a raw `code`."
  @spec fetch_code(module(), term()) :: {:ok, struct()} | :error
  def fetch_code(server, code) when is_binary(code),
    do: found(server.authorization_code_resource().get_by_code(code, actor: ServerActor.new()))

  def fetch_code(_server, _code), do: :error

  @doc "The token row for a raw access token."
  @spec fetch_by_token(module(), term()) :: {:ok, struct()} | :error
  def fetch_by_token(server, token) when is_binary(token),
    do: found(server.access_token_resource().get_by_token(token, actor: ServerActor.new()))

  def fetch_by_token(_server, _token), do: :error

  @doc "The token row for a raw refresh token."
  @spec fetch_by_refresh_token(module(), term()) :: {:ok, struct()} | :error
  def fetch_by_refresh_token(server, refresh_token) when is_binary(refresh_token),
    do: found(server.access_token_resource().get_by_refresh_token(refresh_token, actor: ServerActor.new()))

  def fetch_by_refresh_token(_server, _refresh_token), do: :error

  defp found({:ok, row}), do: {:ok, row}
  defp found({:error, _reason}), do: :error
end
