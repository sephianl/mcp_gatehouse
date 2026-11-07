defmodule McpGatehouse.OAuth.OpaqueToken do
  @moduledoc """
  The one generator for every secret this authorization server hands out —
  client ids, authorization codes, access and refresh tokens — and the one place
  that hashes them for storage.

  Only the hash is persisted. A bearer secret is compared, never read back, so
  there is nothing to decrypt and a leaked table is not a set of usable
  credentials. The hash is unsalted deliberately: the row has to be findable
  from the presented value alone, and 32 random bytes leave nothing to guess.

  They stay opaque rather than becoming JWTs so revocation is immediate — the
  endpoint reads the row on every request rather than waiting for an expiry.
  """

  @bytes 32

  @doc "A fresh 32-byte secret, URL-safe base64 without padding."
  @spec generate() :: String.t()
  def generate, do: @bytes |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

  @doc """
  The stored form of a secret: its SHA-256 as lowercase hex.

  Hex rather than base64 so Postgres' own `encode(sha256(...), 'hex')` produces
  identical values: a host can backfill or audit hashes in SQL, and tokens issued
  before such a migration keep working across it.
  """
  @spec hash(String.t()) :: String.t()
  def hash(secret), do: :sha256 |> :crypto.hash(secret) |> Base.encode16(case: :lower)
end
