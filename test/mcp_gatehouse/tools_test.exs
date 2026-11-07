defmodule McpGatehouse.ToolsTest do
  @moduledoc """
  `report_missing_capability` is served from the library's own domain: it
  advertises the `context` argument every tool takes, accepts it without error,
  and answers with a receipt rather than data.
  """
  use ExUnit.Case, async: true

  alias Ash.Resource.Info
  alias McpGatehouse.CapabilityGap
  alias McpGatehouse.Intent
  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.User
  alias McpGatehouse.Test.Widget

  @receipt "Recorded. No tool covers that today, so answer from what you already have."

  setup do
    user = User.admin()

    %{user: user, token: Flow.mint(user).__metadata__.token}
  end

  defp listed(token) do
    "tools/list"
    |> Flow.rpc(%{}, token)
    |> Flow.json()
    |> get_in(["result", "tools"])
    |> Map.new(&{&1["name"], &1})
  end

  defp text(result), do: result |> Map.fetch!("content") |> List.first() |> Map.fetch!("text")

  test "the tool advertises the action's description and a context argument", %{token: token} do
    %{"report_missing_capability" => tool} = listed(token)

    action = Info.action(CapabilityGap, :report_missing_capability)
    assert tool["description"] == String.trim(action.description)

    input = get_in(tool, ["inputSchema", "properties", "input", "properties"])
    assert input |> Map.keys() |> Enum.sort() == ["capability", "context"]
    assert input["context"]["description"] == Intent.description()
  end

  test "a call carrying context is accepted and answered with a receipt", %{token: token} do
    result =
      Flow.call_tool(
        "report_missing_capability",
        %{
          "input" => %{
            "capability" => "fuel spend per vehicle per week",
            "context" => "which trucks cost most"
          }
        },
        token
      )

    assert result["isError"] == false
    assert Jason.decode!(text(result)) == @receipt
  end

  test "a call without the capability is a tool error", %{token: token} do
    result = Flow.call_tool("report_missing_capability", %{"input" => %{}}, token)

    assert result["isError"] == true
  end

  test "the action needs an actor" do
    assert {:ok, @receipt} = CapabilityGap.report_missing_capability("x", actor: User.admin())
    assert {:error, %Ash.Error.Forbidden{}} = CapabilityGap.report_missing_capability("x")
  end

  test "a host tool reads the tenant's records through the same pipeline", %{
    user: user,
    token: token
  } do
    {:ok, _widget} = Widget.create("sprocket", actor: user)

    result =
      Flow.call_tool("list_widgets", %{"input" => %{"context" => "what is in stock"}}, token)

    assert result["isError"] == false

    assert [%{"name" => "sprocket"}] =
             result |> text() |> Jason.decode!() |> Map.fetch!("results")
  end

  test "a page larger than the cap is refused rather than trimmed", %{token: token} do
    result = Flow.call_tool("list_widgets", %{"limit" => 251}, token)

    assert result["isError"] == true
    assert text(result) =~ "250"
  end
end
