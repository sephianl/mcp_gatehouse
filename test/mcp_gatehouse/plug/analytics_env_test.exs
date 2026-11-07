defmodule McpGatehouse.Plug.AnalyticsEnvTest do
  @moduledoc """
  Phoenix compiles `:phoenix, :filter_parameters` into a tuple at boot, so
  redaction must never read it: a tuple there would raise inside `before_send`,
  after the tool already ran. Not async: it sets Phoenix's env for its duration.
  """
  use ExUnit.Case, async: false

  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.User

  setup do
    previous = Application.fetch_env(:phoenix, :filter_parameters)

    Application.put_env(
      :phoenix,
      :filter_parameters,
      {:compiled, {:ac, make_ref()}, {:ac, make_ref()}}
    )

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:phoenix, :filter_parameters, value)
        :error -> Application.delete_env(:phoenix, :filter_parameters)
      end
    end)
  end

  test "a compiled Phoenix filter does not reach analytics redaction" do
    token = Flow.mint(User.admin()).__metadata__.token
    arguments = %{"input" => %{"capability" => "x", "code_verifier" => "secret"}}

    conn =
      Flow.rpc(
        "tools/call",
        %{"name" => "report_missing_capability", "arguments" => arguments},
        token
      )

    assert conn.status == 200
    assert_received {:captured, "$mcp_missing_capability", _distinct_id, _company_id, properties}

    assert properties[:"$mcp_parameters"] == %{
             "capability" => "x",
             "code_verifier" => "[REDACTED]"
           }
  end
end
