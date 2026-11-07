defmodule McpGatehouse.Plug.Analytics do
  @moduledoc """
  Emits PostHog MCP Analytics events for each JSON-RPC call on the MCP endpoint,
  through `c:McpGatehouse.Server.capture_event/4`.

      plug McpGatehouse.Plug.Analytics

  after `McpGatehouse.Plug.Server` in the pipeline, or with its own
  `server: MyAppWeb.Mcp`.

  Speaks PostHog's `$mcp_*` wire contract, not the `$ai_*` LLM-analytics events:
  this server answers tool calls and never calls a model, so a generation-shaped
  event would have nothing to put in its required model, provider and token fields.

  That contract is pre-1.0 and PostHog reserves the right to change it, which is
  why every `$mcp_*` spelling in the system lives here and nowhere else.

  Outcome has to be read back out of the rendered response: a failed tool call is
  an HTTP 200 carrying `isError`, so the status line cannot tell success from
  failure.

  How much of a call is sent follows `c:McpGatehouse.Server.analytics_payloads/0`:

    * `:envelope` — the envelope, tool name, intent and outcome; no arguments,
      no response and no error message.
    * `:input` (default) — adds `$mcp_parameters` (the tool's `input`, minus
      `context`) and `$mcp_error_message`; no response.
    * `:full` — adds `$mcp_response` as well.

  `$mcp_missing_capability` always carries its `$mcp_parameters`, whatever the
  setting: the capability asked for is that event's whole content. Payloads are
  capped per property and keys matching `c:McpGatehouse.Server.filtered_parameters/0`
  are redacted.

  The event is captured in a `before_send` hook. A failure there is logged and
  the response still goes out, so analytics can never fail a completed tool call.
  """

  @behaviour Plug

  import Plug.Conn

  alias Ash.PlugHelpers
  alias AshAi.Mcp.Server
  alias McpGatehouse.Plug.Options
  alias McpGatehouse.Server.Callbacks

  require Logger

  @source "posthog_mcp_analytics"
  @redacted "[REDACTED]"
  @max_payload_chars 10_000

  @impl Plug
  @spec init(keyword()) :: map()
  def init(opts), do: Options.validate(__MODULE__, opts)

  @impl Plug
  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, opts) do
    server = Options.server(conn, __MODULE__, opts)
    started_at = System.monotonic_time(:millisecond)

    register_before_send(conn, fn sent ->
      capture_safely(server, sent, System.monotonic_time(:millisecond) - started_at)
      sent
    end)
  end

  defp capture_safely(server, sent, duration_ms) do
    capture(sent.params, %{
      server: server,
      conn: sent,
      duration_ms: duration_ms,
      payloads: Callbacks.analytics_payloads(server),
      sensitive: server |> Callbacks.filtered_parameters() |> Enum.map(&String.downcase/1)
    })
  catch
    # Analytics must never fail a completed tool call.
    kind, reason ->
      Logger.warning("MCP analytics capture failed: " <> Exception.format_banner(kind, reason))
  end

  defp capture(%{"method" => "tools/call", "params" => %{"name" => "report_missing_capability"} = params}, call) do
    properties =
      call
      |> envelope(params)
      |> Map.put(:"$mcp_parameters", parameters(params, call))
      |> Map.merge(intent(params))
      |> Map.merge(outcome(call))

    emit("$mcp_missing_capability", call, properties)
  end

  defp capture(%{"method" => "tools/call", "params" => %{"name" => name} = params}, call) do
    properties =
      call
      |> envelope(params)
      |> Map.put(:"$mcp_tool_name", name)
      |> put_parameters(params, call)
      |> Map.merge(intent(params))
      |> Map.merge(outcome(call))

    emit("$mcp_tool_call", call, properties)
  end

  defp capture(%{"method" => "tools/list"} = body, call) do
    properties =
      call
      |> envelope(body["params"] || %{})
      |> Map.put(:"$mcp_listed_tool_names", listed_tool_names(call.conn))

    emit("$mcp_tools_list", call, properties)
  end

  defp capture(%{"method" => "initialize", "params" => params}, call) do
    emit("$mcp_initialize", call, envelope(call, params))
  end

  defp capture(_body, _call), do: :ok

  defp emit(event, %{server: server, conn: conn}, properties) do
    server.capture_event(event, distinct_id(conn), PlugHelpers.get_tenant(conn), properties)
  end

  defp distinct_id(conn) do
    case PlugHelpers.get_actor(conn) do
      %{id: id} when is_binary(id) -> id
      _unauthenticated -> "anonymous"
    end
  end

  defp envelope(%{server: server, conn: conn, duration_ms: duration_ms}, params) do
    Map.merge(
      %{
        "$session_id": session_id(conn),
        "$mcp_source": @source,
        "$mcp_server_name": server.server_name(),
        "$mcp_server_version": Server.get_server_version(otp_app: server.otp_app()),
        "$mcp_protocol_version": protocol_version(params),
        "$mcp_client_user_agent": header(conn, "user-agent"),
        "$mcp_vendor_client": header(conn, "x-anthropic-client"),
        "$mcp_duration_ms": duration_ms
      },
      client_info(params)
    )
  end

  defp session_id(conn) do
    case get_req_header(conn, "mcp-session-id") do
      [id | _rest] -> "ses_" <> digest(id)
      [] -> "ses_" <> digest(conn.private[:request_id] || inspect(self()))
    end
  end

  defp digest(value) do
    :sha256 |> :crypto.hash(value) |> Base.encode16(case: :lower) |> binary_part(0, 32)
  end

  defp header(conn, name) do
    case get_req_header(conn, name) do
      [value | _rest] -> value
      [] -> nil
    end
  end

  defp protocol_version(%{"_meta" => %{"io.modelcontextprotocol/protocolVersion" => version}}), do: version

  defp protocol_version(%{"protocolVersion" => version}), do: version
  defp protocol_version(_params), do: nil

  defp client_info(%{"_meta" => %{"io.modelcontextprotocol/clientInfo" => info}}), do: named_client(info)

  defp client_info(%{"clientInfo" => info}), do: named_client(info)
  defp client_info(_params), do: %{}

  defp named_client(%{"name" => name, "version" => version}),
    do: %{"$mcp_client_name": name, "$mcp_client_version": version}

  defp named_client(_info), do: %{}

  defp intent(%{"arguments" => %{"input" => %{"context" => context}}}) when is_binary(context),
    do: %{"$mcp_intent": context, "$mcp_intent_source": "context_parameter"}

  defp intent(_params), do: %{}

  defp put_parameters(properties, _params, %{payloads: :envelope}), do: properties

  defp put_parameters(properties, params, call), do: Map.put(properties, :"$mcp_parameters", parameters(params, call))

  defp parameters(%{"arguments" => %{"input" => input}}, %{sensitive: sensitive}) when is_map(input) do
    input
    |> Map.delete("context")
    |> redact(sensitive)
    |> capped()
  end

  defp parameters(_params, _call), do: nil

  defp listed_tool_names(conn) do
    case decoded_body(conn) do
      %{"result" => %{"tools" => tools}} when is_list(tools) -> Enum.map(tools, & &1["name"])
      _other -> []
    end
  end

  defp outcome(%{conn: conn, payloads: payloads}) do
    body = decoded_body(conn)

    body
    |> result_properties()
    |> within_payload_policy(payloads)
    |> put_response(body, payloads)
  end

  defp result_properties(%{"result" => %{"isError" => true} = result}),
    do: %{"$mcp_is_error": true, "$mcp_error_message": text_content(result)}

  defp result_properties(%{"error" => %{"message" => message} = error}),
    do: %{"$mcp_is_error": true, "$mcp_error_message": message, "$mcp_error_type": error_type(error)}

  defp result_properties(_body), do: %{"$mcp_is_error": false}

  defp within_payload_policy(properties, :envelope), do: Map.delete(properties, :"$mcp_error_message")

  defp within_payload_policy(properties, _input_or_full), do: properties

  defp put_response(properties, %{"result" => result}, :full), do: Map.put(properties, :"$mcp_response", capped(result))

  defp put_response(properties, _body, _payloads), do: properties

  defp error_type(%{"code" => -32_602}), do: "validation"
  defp error_type(%{"code" => -32_601}), do: "validation"
  defp error_type(_error), do: nil

  defp text_content(%{"content" => [%{"text" => text} | _rest]}), do: truncate(text)
  defp text_content(_result), do: nil

  defp decoded_body(conn) do
    case Jason.decode(IO.iodata_to_binary(conn.resp_body || "")) do
      {:ok, body} when is_map(body) -> body
      _undecodable -> %{}
    end
  end

  defp truncate(value) when is_binary(value), do: String.slice(value, 0, @max_payload_chars)

  defp truncate(value) do
    case Jason.encode(value) do
      {:ok, encoded} -> truncate(encoded)
      {:error, _unencodable} -> nil
    end
  end

  defp capped(value) do
    case Jason.encode(value) do
      {:ok, encoded} when byte_size(encoded) <= @max_payload_chars -> value
      {:ok, encoded} -> truncate(encoded)
      {:error, _unencodable} -> nil
    end
  end

  defp redact(arguments, sensitive) when is_map(arguments) do
    Map.new(arguments, fn {key, value} ->
      if Enum.any?(sensitive, &String.contains?(String.downcase(to_string(key)), &1)) do
        {key, @redacted}
      else
        {key, redact(value, sensitive)}
      end
    end)
  end

  defp redact(arguments, sensitive) when is_list(arguments), do: Enum.map(arguments, &redact(&1, sensitive))

  defp redact(value, _sensitive), do: value
end
