defmodule McpGatehouse.Plug.JsonTest do
  @moduledoc """
  The plugs' JSON responses: a body that encodes goes out as sent, and one that
  does not becomes a 500 `server_error` instead of a crash mid-exchange.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias McpGatehouse.Plug.Json

  test "sends an encodable body as JSON with the given status" do
    conn = :get |> conn("/") |> Json.send_json(201, %{client_id: "abc"})

    assert conn.status == 201
    assert conn.resp_body == ~s({"client_id":"abc"})
    assert ["application/json" <> _charset] = get_resp_header(conn, "content-type")
  end

  test "answers a body that cannot be encoded with a 500 server_error" do
    conn = :get |> conn("/") |> Json.send_json(200, %{client_name: <<0xFF>>})

    assert conn.status == 500
    assert conn.resp_body == ~s({"error":"server_error"})
    assert ["application/json" <> _charset] = get_resp_header(conn, "content-type")
  end
end
