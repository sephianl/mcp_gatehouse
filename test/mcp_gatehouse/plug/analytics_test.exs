defmodule McpGatehouse.Plug.AnalyticsTest do
  @moduledoc """
  The MCP endpoint reports each JSON-RPC call to PostHog's `$mcp_*` contract.

  The properties that carry the analysis are the ones a client supplies and a
  plug cannot infer: which tool ran, which agent asked, and whether it worked —
  the last of which is invisible in the status line, because a failed tool call
  is still an HTTP 200. How much of the call's data goes along is the host's
  choice, except for a reported gap, whose content is the whole point.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog
  import Plug.Conn
  import Plug.Test

  alias McpGatehouse.Test.ConfiguredServer
  alias McpGatehouse.Test.EnvelopeServer
  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.RaisingServer
  alias McpGatehouse.Test.Router
  alias McpGatehouse.Test.User

  @gap %{
    "name" => "report_missing_capability",
    "arguments" => %{
      "input" => %{
        "capability" => "fuel spend per vehicle per week",
        "context" => "user asked which trucks cost the most to run"
      }
    }
  }

  @list_widgets %{
    "name" => "list_widgets",
    "arguments" => %{"input" => %{"context" => "what is in stock"}}
  }

  setup do
    user = User.admin()

    %{user: user, token: Flow.mint(user).__metadata__.token}
  end

  test "an unauthenticated call is not captured" do
    Flow.rpc("tools/list", %{}, nil)

    refute_received {:captured, _event, _distinct_id, _company_id, _properties}
  end

  test "a tool call reports the tool, the agent, the tenant and the outcome", %{
    user: user,
    token: token
  } do
    Flow.rpc("tools/call", @list_widgets, token)

    assert_received {:captured, "$mcp_tool_call", distinct_id, company_id, properties}

    assert distinct_id == user.id
    assert company_id == user.company_id
    assert properties[:"$mcp_tool_name"] == "list_widgets"
    assert properties[:"$mcp_server_name"] == "Test MCP"
    assert properties[:"$mcp_server_version"] == "0.1.0"
    assert properties[:"$mcp_client_name"] == "claude-desktop"
    assert properties[:"$mcp_client_version"] == "9.9.9"
    assert properties[:"$mcp_protocol_version"] == Flow.protocol_version()
    assert properties[:"$mcp_source"] == "posthog_mcp_analytics"
    assert properties[:"$mcp_is_error"] == false
    assert properties[:"$mcp_intent"] == "what is in stock"
    assert properties[:"$mcp_intent_source"] == "context_parameter"
    assert properties[:"$mcp_parameters"] == %{}
    assert is_integer(properties[:"$mcp_duration_ms"])
    assert properties[:"$session_id"] =~ ~r/^ses_[0-9a-f]{32}$/
  end

  test "by default no response is sent", %{token: token} do
    Flow.rpc("tools/call", @list_widgets, token)

    assert_received {:captured, "$mcp_tool_call", _distinct_id, _company_id, properties}
    refute Map.has_key?(properties, :"$mcp_response")
  end

  test "a tool that does not exist is reported as an error, not a success", %{token: token} do
    Flow.rpc("tools/call", %{"name" => "no_such_tool", "arguments" => %{}}, token)

    assert_received {:captured, "$mcp_tool_call", _distinct_id, _company_id, properties}

    assert properties[:"$mcp_is_error"] == true
    assert properties[:"$mcp_error_type"] == "validation"
    assert properties[:"$mcp_error_message"] =~ "no_such_tool"
  end

  test "a context that is not a string is not reported as intent", %{token: token} do
    Flow.rpc(
      "tools/call",
      %{
        "name" => "list_widgets",
        "arguments" => %{"input" => %{"context" => %{"goal" => "stock"}}}
      },
      token
    )

    assert_received {:captured, "$mcp_tool_call", _distinct_id, _company_id, properties}

    refute Map.has_key?(properties, :"$mcp_intent")
    refute Map.has_key?(properties, :"$mcp_intent_source")
  end

  test "a reported gap is captured as a missing capability, carrying what was asked for", %{
    token: token
  } do
    Flow.rpc("tools/call", @gap, token)

    assert_received {:captured, "$mcp_missing_capability", _distinct_id, _company_id, properties}

    assert properties[:"$mcp_parameters"] == %{"capability" => "fuel spend per vehicle per week"}
    assert properties[:"$mcp_intent"] == "user asked which trucks cost the most to run"
    assert properties[:"$mcp_intent_source"] == "context_parameter"
    assert properties[:"$mcp_is_error"] == false
    refute Map.has_key?(properties, :"$mcp_tool_name")
  end

  test "listing tools reports what was advertised", %{token: token} do
    Flow.rpc("tools/list", %{}, token)

    assert_received {:captured, "$mcp_tools_list", _distinct_id, _company_id, properties}

    assert Enum.sort(properties[:"$mcp_listed_tool_names"]) == [
             "list_widgets",
             "report_missing_capability"
           ]
  end

  test "an initialize reports the client and the session", %{token: token} do
    body = %{
      "jsonrpc" => "2.0",
      "id" => 1,
      "method" => "initialize",
      "params" => %{
        "protocolVersion" => "2025-06-18",
        "capabilities" => %{},
        "clientInfo" => %{"name" => "claude-ai", "version" => "0.1.0"}
      }
    }

    :post
    |> conn("/mcp", Jason.encode!(body))
    |> put_req_header("content-type", "application/json")
    |> put_req_header("authorization", "Bearer " <> token)
    |> put_req_header("mcp-session-id", "session-1")
    |> put_req_header("user-agent", "claude-user-agent")
    |> put_req_header("x-anthropic-client", "claude-code")
    |> Router.call(Router.init([]))

    assert_received {:captured, "$mcp_initialize", _distinct_id, _company_id, properties}

    assert properties[:"$mcp_protocol_version"] == "2025-06-18"
    assert properties[:"$mcp_client_name"] == "claude-ai"
    assert properties[:"$mcp_client_version"] == "0.1.0"
    assert properties[:"$mcp_client_user_agent"] == "claude-user-agent"
    assert properties[:"$mcp_vendor_client"] == "claude-code"

    assert properties[:"$session_id"] ==
             "ses_" <>
               (:sha256
                |> :crypto.hash("session-1")
                |> Base.encode16(case: :lower)
                |> binary_part(0, 32))
  end

  test "keys containing a configured filtered parameter are redacted at any depth", %{
    token: token
  } do
    input = %{
      "password" => "hunter2",
      "barcode" => "3SBAR123456",
      "nested" => [
        %{"api_token" => "abc", "postcode" => "1234AB", "payout_iban" => "NL91ABNA0417164300"}
      ]
    }

    Flow.rpc("tools/call", %{"name" => "list_widgets", "arguments" => %{"input" => input}}, token)

    assert_received {:captured, "$mcp_tool_call", _distinct_id, _company_id, properties}

    assert properties[:"$mcp_parameters"] == %{
             "password" => "[REDACTED]",
             "barcode" => "3SBAR123456",
             "nested" => [
               %{
                 "api_token" => "[REDACTED]",
                 "postcode" => "1234AB",
                 "payout_iban" => "[REDACTED]"
               }
             ]
           }
  end

  test "an oversized argument is capped", %{token: token} do
    input = %{"capability" => String.duplicate("x", 20_000)}

    Flow.rpc(
      "tools/call",
      %{"name" => "report_missing_capability", "arguments" => %{"input" => input}},
      token
    )

    assert_received {:captured, "$mcp_missing_capability", _distinct_id, _company_id, properties}

    assert is_binary(properties[:"$mcp_parameters"])
    assert String.length(properties[:"$mcp_parameters"]) == 10_000
  end

  describe "with analytics_payloads :envelope" do
    test "a tool call carries no arguments, response or error text", %{token: token} do
      Flow.rpc_through(
        EnvelopeServer,
        "tools/call",
        %{"name" => "no_such_tool", "arguments" => %{"input" => %{"a" => 1}}},
        token
      )

      assert_received {:captured, "$mcp_tool_call", _distinct_id, _company_id, properties}

      assert properties[:"$mcp_is_error"] == true
      assert properties[:"$mcp_tool_name"] == "no_such_tool"

      for dropped <- [:"$mcp_parameters", :"$mcp_response", :"$mcp_error_message"] do
        refute Map.has_key?(properties, dropped), "#{dropped} was sent"
      end
    end

    test "a successful tool call keeps its intent", %{token: token} do
      Flow.rpc_through(EnvelopeServer, "tools/call", @list_widgets, token)

      assert_received {:captured, "$mcp_tool_call", _distinct_id, _company_id, properties}

      assert properties[:"$mcp_intent"] == "what is in stock"
      refute Map.has_key?(properties, :"$mcp_parameters")
      refute Map.has_key?(properties, :"$mcp_response")
    end

    test "a reported gap still carries what was asked for", %{token: token} do
      Flow.rpc_through(EnvelopeServer, "tools/call", @gap, token)

      assert_received {:captured, "$mcp_missing_capability", _distinct_id, _company_id, properties}

      assert properties[:"$mcp_parameters"] == %{
               "capability" => "fuel spend per vehicle per week"
             }

      refute Map.has_key?(properties, :"$mcp_response")
    end
  end

  describe "with analytics_payloads :full and the host's own redaction list" do
    test "a tool call carries its response", %{token: token} do
      Flow.rpc_through(ConfiguredServer, "tools/call", @list_widgets, token)

      assert_received {:captured, "$mcp_tool_call", _distinct_id, _company_id, properties}

      assert %{"isError" => false, "content" => [_text | _more]} = properties[:"$mcp_response"]
    end

    test "a failed tool call carries its error text and response", %{token: token} do
      Flow.rpc_through(
        ConfiguredServer,
        "tools/call",
        %{"name" => "list_widgets", "arguments" => %{"limit" => 251}},
        token
      )

      assert_received {:captured, "$mcp_tool_call", _distinct_id, _company_id, properties}

      assert properties[:"$mcp_is_error"] == true
      assert properties[:"$mcp_error_message"] =~ "250"
      assert %{"isError" => true} = properties[:"$mcp_response"]
    end

    test "redaction follows filtered_parameters/0", %{token: token} do
      input = %{"fuel_card" => "1234", "password" => "kept"}

      Flow.rpc_through(
        ConfiguredServer,
        "tools/call",
        %{"name" => "list_widgets", "arguments" => %{"input" => input}},
        token
      )

      assert_received {:captured, "$mcp_tool_call", _distinct_id, _company_id, properties}

      assert properties[:"$mcp_parameters"] == %{
               "fuel_card" => "[REDACTED]",
               "password" => "kept"
             }
    end

    test "a mixed-case pattern redacts a key in any case", %{token: token} do
      input = %{"APIKEY" => "k-123", "apikey_hint" => "rotate monthly", "api" => "v2"}

      Flow.rpc_through(
        ConfiguredServer,
        "tools/call",
        %{"name" => "list_widgets", "arguments" => %{"input" => input}},
        token
      )

      assert_received {:captured, "$mcp_tool_call", _distinct_id, _company_id, properties}

      assert properties[:"$mcp_parameters"] == %{
               "APIKEY" => "[REDACTED]",
               "apikey_hint" => "[REDACTED]",
               "api" => "v2"
             }
    end
  end

  test "a failing analytics backend does not fail the tool call", %{token: token} do
    log =
      capture_log(fn ->
        conn = Flow.rpc_through(RaisingServer, "tools/call", @gap, token)

        assert conn.status == 200
        assert conn |> Flow.json() |> get_in(["result", "isError"]) == false
      end)

    assert log =~ "MCP analytics capture failed"
    assert log =~ "analytics backend is down"
  end
end
