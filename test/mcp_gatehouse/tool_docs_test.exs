defmodule McpGatehouse.ToolDocsTest do
  @moduledoc """
  The page cap an MCP tool describes has to be the one its action enforces.

  A model told it may ask for 250 and then refused at 100 has no way to recover,
  so these walk every registered tool rather than trusting the two numbers to
  stay equal by inspection.
  """
  use ExUnit.Case, async: true

  alias McpGatehouse.Intent
  alias McpGatehouse.ToolDocs

  defp mcp_tools do
    for domain <- Application.fetch_env!(:mcp_gatehouse, :ash_domains),
        tool <- AshAi.Info.tools(domain) do
      {tool.name, tool, Ash.Resource.Info.action(tool.resource, tool.action)}
    end
  end

  defp promises_paging?(%AshAi.Tool{description: nil}), do: false

  defp promises_paging?(%AshAi.Tool{description: description}), do: String.contains?(description, ToolDocs.paging())

  defp max_page_size(%Ash.Resource.Actions.Read{pagination: %Ash.Resource.Actions.Read.Pagination{max_page_size: max}}),
    do: max

  defp max_page_size(_action), do: nil

  describe "page_cap/0" do
    test "is the cap enforced by every tool whose description promises it" do
      promising =
        for {name, tool, action} <- mcp_tools(),
            promises_paging?(tool),
            do: {name, max_page_size(action)}

      refute promising == [],
             "no MCP tool description contains the paging paragraph — the introspection below found nothing to check"

      for {name, max_page_size} <- promising do
        assert max_page_size == ToolDocs.page_cap(),
               "#{name} promises #{ToolDocs.page_cap()} records per call but its action caps at #{inspect(max_page_size)}"
      end
    end
  end

  describe "paging/0" do
    test "names the cap it enforces rather than a literal of its own" do
      assert ToolDocs.paging() =~ "#{ToolDocs.page_cap()}"
      assert ToolDocs.page_cap() == 250
    end

    test "tells the model to follow the keyset" do
      assert ToolDocs.paging() =~ "pass the page's `end_keyset` as `after`"
    end
  end

  describe "grouping/1" do
    test "names the groupings the caller passed in" do
      assert ToolDocs.grouping("per depot, per route, per day") =~ "per depot, per route, per day"
    end

    test "warns about the scan limit grouping refuses past" do
      assert ToolDocs.grouping("per depot") =~ "25,000"
    end
  end

  test "every tool takes the context argument" do
    for {name, tool, _action} <- mcp_tools() do
      assert [%{name: :context, description: description}] =
               Enum.filter(tool.arguments, &(&1.name == :context)),
             "#{name} does not take a context argument"

      assert description == Intent.description()
    end
  end

  test "the intent prompt text is stable, so analytics grouped on it stay comparable" do
    assert Intent.description() ==
             "Why are you calling this tool? Briefly describe the user's goal."
  end
end
