defmodule McpGatehouse.OAuth.ServerActor do
  @moduledoc """
  A token row has to be read before anyone is authenticated, because the token
  is what names the user, so that read cannot carry the caller's actor. This
  stands in for one: `McpGatehouse.OAuth.Checks.ServerActor` authorizes it on the
  OAuth resources, and a host grants it a single user lookup and nothing else.

  It is its own struct rather than a user with a reserved role, so no stored
  account can ever hold it: there is no row to sign in as and no password hash
  to leak, and it carries no company, so every company-scoped policy elsewhere
  rejects it.
  """

  defstruct []

  @type t :: %__MODULE__{}

  @doc "The actor every OAuth-table action runs as."
  @spec new() :: t()
  def new, do: %__MODULE__{}
end
