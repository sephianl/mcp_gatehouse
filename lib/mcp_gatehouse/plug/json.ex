defmodule McpGatehouse.Plug.Json do
  @moduledoc """
  Sends the JSON bodies the library's plugs answer with, without a bang encode:
  a body that cannot be encoded becomes a 500 `server_error` rather than a crash
  in the middle of an OAuth exchange.
  """

  import Plug.Conn

  @server_error ~s({"error":"server_error"})

  @doc "Sends `body` as JSON with `status`."
  @spec send_json(Plug.Conn.t(), Plug.Conn.status(), term()) :: Plug.Conn.t()
  def send_json(conn, status, body) do
    case Jason.encode(body) do
      {:ok, encoded} -> send_encoded(conn, status, encoded)
      {:error, _reason} -> send_encoded(conn, 500, @server_error)
    end
  end

  defp send_encoded(conn, status, encoded) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, encoded)
  end
end
