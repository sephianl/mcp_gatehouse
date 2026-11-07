defmodule McpGatehouse.OAuth.Scopes do
  @moduledoc """
  The scopes an MCP access token can carry.

  These are deliberately separate from any scopes a host's other OAuth server
  issues, whose reach is usually whatever the owning user's role allows. An MCP
  token is handed to a model that chooses its own tool calls, so its reach has to
  be expressible independently of the human behind it.

  How a scope is described to the person approving it is the host's to word and
  translate.
  """

  @read "mcp:read"

  @doc "The read scope, the only one granted today."
  @spec read() :: String.t()
  def read, do: @read

  @doc "Every scope this server grants."
  @spec all() :: [String.t()]
  def all, do: [@read]

  @doc """
  Narrows a requested scope string to the ones we actually grant. An unknown
  scope is dropped rather than rejected, per RFC 6749 §3.3, and so is a request
  that is not a string at all, such as a JSON list.
  """
  @spec granted(term()) :: [String.t()]
  def granted(nil), do: [@read]
  def granted(""), do: [@read]

  def granted(requested) when is_binary(requested) do
    case requested |> String.split(~r/\s+/, trim: true) |> Enum.filter(&(&1 in all())) do
      [] -> [@read]
      scopes -> scopes
    end
  end

  def granted(_not_a_string), do: [@read]
end
