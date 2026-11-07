defmodule McpGatehouse.ClientIpTest do
  @moduledoc """
  The rate-limit key has to be an address the caller cannot choose: the client
  is the right-most `X-Forwarded-For` entry that is not a trusted proxy, and no
  other forwarding header is believed.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias McpGatehouse.ClientIp

  @trusted ["35.191.0.0/16", "130.211.0.0/22"]

  defp resolve(headers, trusted \\ @trusted) do
    headers
    |> Enum.reduce(conn(:get, "/"), fn {name, value}, acc -> put_req_header(acc, name, value) end)
    |> ClientIp.resolve(trusted)
  end

  test "without a forwarding header the socket peer is the client" do
    assert resolve([]) == "127.0.0.1"

    assert :get |> conn("/") |> Map.put(:remote_ip, {198, 51, 100, 4}) |> ClientIp.resolve([]) ==
             "198.51.100.4"
  end

  test "the address our ingress appended wins over one the caller wrote" do
    assert resolve([{"x-forwarded-for", "6.6.6.6, 203.0.113.7"}]) == "203.0.113.7"
  end

  test "trusted proxies are walked past from the right" do
    assert resolve([{"x-forwarded-for", "203.0.113.7, 130.211.0.9, 35.191.0.5"}]) == "203.0.113.7"
  end

  test "an untrusted proxy over-collapses rather than reaching a forged entry" do
    assert resolve([{"x-forwarded-for", "6.6.6.6, 203.0.113.7, 35.191.0.5"}], []) == "35.191.0.5"
  end

  test "private hops are skipped even with no proxies configured" do
    assert resolve([{"x-forwarded-for", "203.0.113.7, 10.0.0.12"}], []) == "203.0.113.7"
  end

  test "forged x-real-ip, x-client-ip and forwarded headers after XFF are ignored" do
    xff = {"x-forwarded-for", "203.0.113.7, 35.191.0.5"}

    for forged <- [
          {"x-real-ip", "6.6.6.6"},
          {"x-client-ip", "7.7.7.7"},
          {"forwarded", "for=8.8.4.4"},
          {"x-real-ip", "2001:db8::1"}
        ] do
      assert resolve([xff, forged]) == "203.0.113.7", "#{inspect(forged)} chose the bucket"
    end
  end

  test "forwarding headers other than XFF are never read on their own" do
    assert resolve([{"x-real-ip", "6.6.6.6"}, {"forwarded", "for=8.8.4.4"}]) == "127.0.0.1"
  end

  test "IPv6 clients resolve" do
    assert resolve([{"x-forwarded-for", "2001:db8::1, 35.191.0.5"}]) == "2001:db8::1"
  end
end
