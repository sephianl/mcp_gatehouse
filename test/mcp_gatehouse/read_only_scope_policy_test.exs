defmodule McpGatehouse.ReadOnlyScopePolicyTest do
  @moduledoc """
  A token granted only `mcp:read` cannot create, update or destroy in a domain
  carrying the policy, while reads and generic actions — the shape of
  `report_missing_capability` — stay open, and requests that did not come
  through MCP are untouched.
  """
  use ExUnit.Case, async: true

  alias Ash.Error.Forbidden
  alias McpGatehouse.Checks.McpTokenLacksWriteScope
  alias McpGatehouse.Test.User
  alias McpGatehouse.Test.Widget

  setup do
    user = User.admin()
    {:ok, widget} = Widget.create("sprocket", actor: user)

    %{user: user, widget: widget}
  end

  defp as_mcp(user, scopes), do: [actor: user, context: %{mcp_scopes: scopes}]

  test "a read-only token cannot create, update or destroy", %{user: user, widget: widget} do
    opts = as_mcp(user, ["mcp:read"])

    assert {:error, %Forbidden{}} = Widget.create("gear", opts)
    assert {:error, %Forbidden{}} = Widget.rename(widget, "gear", opts)
    assert {:error, %Forbidden{}} = Widget.remove(widget, opts)
  end

  test "a read-only token can still read and run generic actions", %{user: user} do
    opts = as_mcp(user, ["mcp:read"])

    assert {:ok, %Ash.Page.Keyset{results: [%Widget{name: "sprocket"}]}} =
             Widget.list(Keyword.put(opts, :page, limit: 10))

    assert {:ok, 0} = Widget.count_widgets(opts)
  end

  test "a token granted mcp:write is not restricted by the policy", %{user: user} do
    assert {:ok, %Widget{}} = Widget.create("gear", as_mcp(user, ["mcp:read", "mcp:write"]))
  end

  test "a request that did not come through MCP is not restricted", %{user: user} do
    assert {:ok, %Widget{}} = Widget.create("gear", actor: user)
  end

  test "the check only matches a scope list without mcp:write" do
    assert McpTokenLacksWriteScope.match?(
             nil,
             %{subject: %{context: %{mcp_scopes: ["mcp:read"]}}},
             []
           )

    assert McpTokenLacksWriteScope.match?(nil, %{subject: %{context: %{mcp_scopes: []}}}, [])

    refute McpTokenLacksWriteScope.match?(
             nil,
             %{subject: %{context: %{mcp_scopes: ["mcp:write"]}}},
             []
           )

    refute McpTokenLacksWriteScope.match?(
             nil,
             %{subject: %{context: %{mcp_scopes: "mcp:read"}}},
             []
           )

    refute McpTokenLacksWriteScope.match?(nil, %{subject: %{context: %{}}}, [])
  end
end
