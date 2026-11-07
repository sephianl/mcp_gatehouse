defmodule McpGatehouse.OAuth.RedirectUri do
  @moduledoc """
  The one parser for redirect URIs. Registration, the authorization endpoint
  and the consent page's CSP origin all use it, so the host the consent page
  names is the host the browser is sent to.

  `URI.parse/1` is lenient where browsers are not. It reads
  `https://evil.example\\@claude.ai/cb` as host `claude.ai` with userinfo
  `evil.example\\`, while a browser's WHATWG parser takes the backslash for a
  slash and goes to `evil.example`. So a redirect URI must parse under RFC 3986
  with `URI.new/1`, which refuses the backslash, must carry no userinfo, and
  must name a host of plain hostname characters (no percent-encoding) or the
  loopback `::1`.

  The scheme, loopback and fragment rules sit on top of this, in
  `McpGatehouse.OAuth.Validations.RedirectUris`.
  """

  @plain_host ~r/\A(?:[A-Za-z0-9.-]+|::1)\z/

  @doc "Parses `uri` strictly, returning `:error` for anything a browser could read differently."
  @spec parse(term()) :: {:ok, URI.t()} | :error
  def parse(uri) when is_binary(uri) do
    with {:ok, %URI{userinfo: nil, host: host} = parsed} when is_binary(host) <- URI.new(uri),
         true <- Regex.match?(@plain_host, host) do
      {:ok, parsed}
    else
      _rejected -> :error
    end
  end

  def parse(_uri), do: :error
end
