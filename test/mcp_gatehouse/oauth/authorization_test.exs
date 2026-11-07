defmodule McpGatehouse.OAuth.AuthorizationTest do
  @moduledoc """
  The consent step. The request is checked in a fixed order, the approving
  user's identity — not anything the client sent — decides the tenant, a user
  the host does not let consent is turned away with `access_denied`, and every
  callback names this server as its issuer.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias McpGatehouse.OAuth.Authorization
  alias McpGatehouse.OAuth.ServerActor
  alias McpGatehouse.Test.AuthorizationCode
  alias McpGatehouse.Test.Client
  alias McpGatehouse.Test.Flow
  alias McpGatehouse.Test.Server
  alias McpGatehouse.Test.User

  @issuer "https://mcp.example.test"

  setup do
    %{"client_id" => client_id} = Flow.register()
    {_verifier, challenge} = Flow.pkce()

    %{client_id: client_id, challenge: challenge}
  end

  defp params(client_id, challenge, overrides \\ %{}), do: Flow.authorize_params(client_id, challenge, overrides)

  describe "validate/2" do
    test "describes a valid request for the consent page", %{
      client_id: client_id,
      challenge: challenge
    } do
      assert {:ok, %Authorization{} = authorization} =
               Authorization.validate(Server, params(client_id, challenge))

      assert authorization.client_id == client_id
      assert authorization.client_name == "Claude"
      assert authorization.redirect_uri == Flow.redirect_uri()
      assert authorization.redirect_host == "claude.ai"
      assert authorization.code_challenge == challenge
      assert authorization.state == "opaque-state"
      assert authorization.scopes == ["mcp:read"]
    end

    test "names an unnamed client by its id and narrows unknown scopes", %{challenge: challenge} do
      %{"client_id" => unnamed} = Flow.register(%{"client_name" => nil})

      {:ok, authorization} =
        Authorization.validate(Server, params(unnamed, challenge, %{"scope" => "everything"}))

      assert authorization.client_name == unnamed
      assert authorization.scopes == ["mcp:read"]
    end

    test "an unregistered client comes first, whatever else is wrong", %{challenge: challenge} do
      bad =
        params("never-registered", challenge, %{
          "redirect_uri" => "https://evil.example/cb",
          "response_type" => "token"
        })

      assert {:error,
              %{
                error: "invalid_client",
                error_description:
                  "this client_id is not registered; discard any stored registration and register again at /mcp/oauth/register"
              }} = Authorization.validate(Server, bad)

      assert {:error, %{error: "invalid_client"}} =
               Authorization.validate(Server, Map.delete(bad, "client_id"))
    end

    test "then a redirect uri the client did not register", %{
      client_id: client_id,
      challenge: challenge
    } do
      bad =
        params(client_id, challenge, %{
          "redirect_uri" => "https://evil.example/cb",
          "response_type" => "token"
        })

      assert {:error,
              %{
                error: "invalid_redirect_uri",
                error_description: "redirect_uri is not registered for this client"
              }} =
               Authorization.validate(Server, bad)

      assert {:error, %{error: "invalid_redirect_uri"}} =
               Authorization.validate(
                 Server,
                 Map.delete(params(client_id, challenge), "redirect_uri")
               )
    end

    test "then a response type other than code", %{client_id: client_id} do
      bad = params(client_id, "", %{"response_type" => "token"})

      assert {:error,
              %{
                error: "unsupported_response_type",
                error_description: "response_type must be code"
              }} =
               Authorization.validate(Server, bad)
    end

    test "an absent response type is read as code", %{client_id: client_id, challenge: challenge} do
      assert {:ok, _authorization} =
               Authorization.validate(
                 Server,
                 Map.delete(params(client_id, challenge), "response_type")
               )
    end

    test "then an S256 challenge", %{client_id: client_id, challenge: challenge} do
      for bad <- [
            Map.delete(params(client_id, challenge), "code_challenge"),
            params(client_id, ""),
            params(client_id, challenge, %{"code_challenge_method" => "plain"}),
            Map.delete(params(client_id, challenge), "code_challenge_method")
          ] do
        assert {:error,
                %{
                  error: "invalid_request",
                  error_description: "code_challenge with S256 is required"
                }} =
                 Authorization.validate(Server, bad)
      end
    end

    test "then a state or scope that is not a string", %{
      client_id: client_id,
      challenge: challenge
    } do
      for {name, value} <- [
            {"scope", ["mcp:read"]},
            {"state", ["a", "b"]},
            {"state", %{"nested" => "x"}}
          ] do
        assert {:error, %{error: "invalid_request", error_description: description}} =
                 Authorization.validate(Server, params(client_id, challenge, %{name => value}))

        assert description == "#{name} must be a string"
      end
    end
  end

  describe "approve/3" do
    test "issues a code carrying the approving user's company", %{
      client_id: client_id,
      challenge: challenge
    } do
      user = User.admin()
      {:ok, authorization} = Authorization.validate(Server, params(client_id, challenge))

      assert {:ok, callback} = Authorization.approve(Server, authorization, user)

      query = Flow.query(callback)
      assert query["state"] == "opaque-state"
      assert query["iss"] == @issuer

      {:ok, code} = AuthorizationCode.get_by_code(query["code"], actor: ServerActor.new())
      assert code.user_id == user.id
      assert code.company_id == user.company_id
      assert code.client_id == client_id
      assert code.redirect_uri == Flow.redirect_uri()
      assert code.code_challenge == challenge
      assert code.code_challenge_method == :S256
      assert code.scopes == ["mcp:read"]
    end

    test "a user the host does not let consent gets access_denied", %{
      client_id: client_id,
      challenge: challenge
    } do
      {:ok, authorization} = Authorization.validate(Server, params(client_id, challenge))

      assert {:ok, callback} = Authorization.approve(Server, authorization, User.worker())

      assert Flow.query(callback) == %{
               "error" => "access_denied",
               "state" => "opaque-state",
               "iss" => @issuer
             }
    end

    test "a code that cannot be issued gets server_error", %{
      client_id: client_id,
      challenge: challenge
    } do
      {:ok, authorization} = Authorization.validate(Server, params(client_id, challenge))

      assert {:ok, callback} =
               Authorization.approve(Server, %{authorization | code_challenge: nil}, User.admin())

      assert Flow.query(callback) == %{
               "error" => "server_error",
               "state" => "opaque-state",
               "iss" => @issuer
             }
    end

    test "a registered redirect uri that already has a query keeps it", %{challenge: challenge} do
      with_query = "https://claude.ai/cb?tenant=acme"
      %{"client_id" => client_id} = Flow.register(%{"redirect_uris" => [with_query]})

      {:ok, authorization} =
        Authorization.validate(
          Server,
          params(client_id, challenge, %{"redirect_uri" => with_query})
        )

      {:ok, callback} = Authorization.approve(Server, authorization, User.admin())

      assert String.starts_with?(callback, "https://claude.ai/cb?")
      assert length(String.split(callback, "?")) == 2
      assert %{"tenant" => "acme", "code" => _code, "iss" => @issuer} = Flow.query(callback)
    end

    test "no state is added when the client sent none", %{
      client_id: client_id,
      challenge: challenge
    } do
      {:ok, authorization} =
        Authorization.validate(Server, Map.delete(params(client_id, challenge), "state"))

      {:ok, callback} = Authorization.approve(Server, authorization, User.admin())

      refute Map.has_key?(Flow.query(callback), "state")
    end
  end

  describe "deny/2" do
    test "returns access_denied with the state and issuer", %{
      client_id: client_id,
      challenge: challenge
    } do
      assert {:ok, callback} = Authorization.deny(Server, params(client_id, challenge))

      assert Flow.query(callback) == %{
               "error" => "access_denied",
               "state" => "opaque-state",
               "iss" => @issuer
             }
    end

    test "needs only the client and its redirect uri", %{client_id: client_id} do
      assert {:ok, _callback} =
               Authorization.deny(Server, %{
                 "client_id" => client_id,
                 "redirect_uri" => Flow.redirect_uri()
               })
    end

    test "refuses a state the callback could not carry, but not a malformed scope", %{
      client_id: client_id,
      challenge: challenge
    } do
      assert {:error, %{error: "invalid_request", error_description: "state must be a string"}} =
               Authorization.deny(Server, params(client_id, challenge, %{"state" => ["a", "b"]}))

      assert {:ok, _callback} =
               Authorization.deny(
                 Server,
                 params(client_id, challenge, %{"scope" => ["mcp:read"]})
               )
    end

    test "refuses an unregistered client or redirect uri", %{
      client_id: client_id,
      challenge: challenge
    } do
      assert {:error, %{error: "invalid_client"}} =
               Authorization.deny(Server, params("never-registered", challenge))

      assert {:error, %{error: "invalid_redirect_uri"}} =
               Authorization.deny(
                 Server,
                 params(client_id, challenge, %{"redirect_uri" => "https://evil.example/cb"})
               )
    end
  end

  describe "a redirect uri registered before registration parsed strictly" do
    @spoofing_uri "https://evil.example\\@claude.ai/api/mcp/auth_callback"

    setup do
      Ash.Seed.seed!(Client, %{
        client_id: "registered-before-the-fix",
        client_name: "Claude",
        redirect_uris: [@spoofing_uri]
      })

      :ok
    end

    test "is refused by validate/2 and deny/2, so the consent page never names the wrong host", %{
      challenge: challenge
    } do
      params = params("registered-before-the-fix", challenge, %{"redirect_uri" => @spoofing_uri})

      for result <- [Authorization.validate(Server, params), Authorization.deny(Server, params)] do
        assert result ==
                 {:error,
                  %{
                    error: "invalid_redirect_uri",
                    error_description: "redirect_uri must have a plain host and no userinfo; register the client again"
                  }}
      end
    end
  end

  describe "permit_form_redirect/2" do
    defp authorization_for(redirect_uri) do
      %Authorization{
        client_id: "c",
        client_name: "c",
        redirect_uri: redirect_uri,
        redirect_host: "h",
        code_challenge: "x",
        state: nil,
        scopes: ["mcp:read"]
      }
    end

    defp with_policy(policy), do: :get |> conn("/") |> put_resp_header("content-security-policy", policy)

    test "widens form-action to the redirect origin" do
      [policy] =
        "default-src 'self'; form-action 'self'"
        |> with_policy()
        |> Authorization.permit_form_redirect(authorization_for(Flow.redirect_uri()))
        |> get_resp_header("content-security-policy")

      assert policy == "default-src 'self'; form-action 'self' https://claude.ai:443"
    end

    test "brackets a loopback IPv6 host and keeps its port" do
      [policy] =
        "form-action 'self'"
        |> with_policy()
        |> Authorization.permit_form_redirect(authorization_for("http://[::1]:33418/callback"))
        |> get_resp_header("content-security-policy")

      assert policy == "form-action 'self' http://[::1]:33418"
    end

    test "adds no origin for a redirect uri that does not parse strictly" do
      policy = "form-action 'self'"

      for redirect_uri <- [
            "https://evil.example\\@claude.ai/cb",
            "https://claude.ai@evil.example/cb"
          ] do
        assert policy
               |> with_policy()
               |> Authorization.permit_form_redirect(authorization_for(redirect_uri))
               |> get_resp_header("content-security-policy") == [policy]
      end
    end

    test "leaves a policy without form-action untouched" do
      policy = "base-uri 'self';  frame-ancestors 'self';"

      assert policy
             |> with_policy()
             |> Authorization.permit_form_redirect(authorization_for(Flow.redirect_uri()))
             |> get_resp_header("content-security-policy") == [policy]
    end

    test "adds no policy where there was none" do
      assert :get
             |> conn("/")
             |> Authorization.permit_form_redirect(authorization_for(Flow.redirect_uri()))
             |> get_resp_header("content-security-policy") == []
    end
  end
end
