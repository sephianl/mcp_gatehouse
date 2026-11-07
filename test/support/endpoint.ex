defmodule McpGatehouse.Test.Endpoint do
  @moduledoc "Stands in for a Phoenix endpoint: the two functions the library builds URLs from."

  @spec url() :: String.t()
  def url, do: "https://mcp.example.test"

  @spec path(String.t()) :: String.t()
  def path(path), do: path
end
