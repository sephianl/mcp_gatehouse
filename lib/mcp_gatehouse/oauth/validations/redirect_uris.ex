defmodule McpGatehouse.OAuth.Validations.RedirectUris do
  @moduledoc """
  A registered redirect URI is the only thing stopping dynamic client
  registration from turning this server into an open redirector, so it is
  checked here rather than at the endpoint: https everywhere, except loopback,
  which local IDE clients need and which cannot be intercepted off-machine.

  Each URI must parse under `McpGatehouse.OAuth.RedirectUri.parse/1`: no
  userinfo, no backslash, a plain host. A URI with a fragment is refused as
  RFC 6749 §3.1.2 requires. Registration is open to anyone, so a client
  registers at most 10 URIs of at most 2,000 characters each.

  The scheme, loopback, fragment and size rules run on registration only, so
  clients registered before them keep working. The strict parse also runs at
  authorization, in `McpGatehouse.OAuth.Authorization`, so a client registered
  before it with a URI a browser reads differently is refused there.
  """
  use Ash.Resource.Validation

  alias Ash.Error.Changes.InvalidAttribute
  alias McpGatehouse.OAuth.RedirectUri

  @loopback_hosts ~w(localhost 127.0.0.1 ::1)
  @max_uris 10
  @max_uri_length 2000

  @impl true
  @spec validate(Ash.Changeset.t(), keyword(), Ash.Resource.Validation.Context.t()) ::
          :ok | {:error, term()}
  def validate(changeset, _opts, _context) do
    changeset
    |> Ash.Changeset.get_attribute(:redirect_uris)
    |> validate_all()
  end

  defp validate_all(uris) when is_list(uris) and uris != [] and length(uris) <= @max_uris do
    if Enum.all?(uris, &acceptable?/1), do: :ok, else: invalid()
  end

  defp validate_all(_uris), do: invalid()

  defp acceptable?(uri) when is_binary(uri) and byte_size(uri) <= @max_uri_length do
    case RedirectUri.parse(uri) do
      {:ok, parsed} -> acceptable_uri?(parsed)
      :error -> false
    end
  end

  defp acceptable?(_uri), do: false

  defp acceptable_uri?(%URI{fragment: fragment}) when is_binary(fragment), do: false
  defp acceptable_uri?(%URI{scheme: "https"}), do: true
  defp acceptable_uri?(%URI{scheme: "http", host: host}) when host in @loopback_hosts, do: true
  defp acceptable_uri?(_uri), do: false

  defp invalid do
    {:error,
     InvalidAttribute.exception(
       field: :redirect_uris,
       message:
         "must be 1 to #{@max_uris} https URIs, or http on loopback, of at most #{@max_uri_length} " <>
           "characters each, with a plain host and no userinfo or fragment"
     )}
  end
end
