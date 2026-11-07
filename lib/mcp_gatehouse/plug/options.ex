defmodule McpGatehouse.Plug.Options do
  @moduledoc """
  Validates a library plug's keyword options in `init/1`, and resolves the
  host's `McpGatehouse.Server` for it in `call/2`.

  Every library plug runs against a server module, named either by its own
  `server:` option or by `McpGatehouse.Plug.Server` earlier in the pipeline,
  which puts it on the connection. `server/3` prefers the option, then the
  connection, and raises when neither names one: a plug without a server is a
  wiring mistake, and failing the request is the only safe answer to it —
  `McpGatehouse.Plug.Bearer` in particular must never let such a request
  through.

  Production routers compile pipeline plugs, running `init/1` once while the
  router compiles, so it only checks and normalises literal options here. The
  server module is never called from `init/1`; every `server.*` call and every
  application env read happens per request in `call/2`.
  """

  @private_key :mcp_gatehouse_server
  @server [server: [type: {:custom, __MODULE__, :validate_server, []}]]

  @doc """
  Validates the options of a plug that takes nothing but `server:`. See
  `validate/3`.
  """
  @spec validate(module(), keyword()) :: map()
  def validate(plug, opts), do: validate(plug, [], opts)

  @doc """
  Validates `opts` against an optional `server:` plus `schema` and returns them
  as a map, raising `ArgumentError` naming `plug` on a missing or invalid
  option. A `server:` entry in `schema` replaces the optional one.
  """
  @spec validate(module(), Spark.Options.schema(), keyword()) :: map()
  def validate(plug, schema, opts) do
    case Spark.Options.validate(opts, Keyword.merge(@server, schema)) do
      {:ok, validated} -> Map.new(validated)
      {:error, error} -> raise ArgumentError, "#{inspect(plug)}: #{Exception.message(error)}"
    end
  end

  @doc false
  @spec validate_server(term()) :: {:ok, module()} | {:error, String.t()}
  def validate_server(server) when is_atom(server) and not is_nil(server), do: {:ok, server}
  def validate_server(server), do: {:error, "expected a module, got: #{inspect(server)}"}

  @doc "Puts `server` on the connection for the library plugs after it."
  @spec put_server(Plug.Conn.t(), module()) :: Plug.Conn.t()
  def put_server(conn, server), do: Plug.Conn.put_private(conn, @private_key, server)

  @doc """
  The server `plug` runs against: its own `server:` option, else the one
  `McpGatehouse.Plug.Server` put on `conn`. Raises `ArgumentError` naming `plug`
  and both ways to configure it when neither is there.
  """
  @spec server(Plug.Conn.t(), module(), map()) :: module()
  def server(_conn, _plug, %{server: server}), do: server
  def server(%Plug.Conn{private: %{@private_key => server}}, _plug, _opts), do: server

  def server(_conn, plug, _opts) do
    raise ArgumentError,
          "#{inspect(plug)} has no MCP server: put `plug McpGatehouse.Plug.Server, server: MyAppWeb.Mcp` " <>
            "in the pipeline ahead of it, or pass it `server: MyAppWeb.Mcp`"
  end
end
