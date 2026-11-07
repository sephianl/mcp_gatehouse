defmodule McpGatehouse.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/sephianl/mcp_gatehouse"

  def project do
    [
      app: :mcp_gatehouse,
      version: @version,
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      source_url: @source_url,
      docs: docs(),
      dialyzer: [
        plt_add_apps: [:ex_unit, :mix],
        plt_local_path: "priv/plts",
        plt_core_path: "priv/plts"
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {McpGatehouse.Application, []}
    ]
  end

  defp description do
    "OAuth 2.1 authorization server and request plumbing (bearer auth, consent, " <>
      "rate limiting, analytics, scope policy) for MCP servers built with ash_ai on Ash and Phoenix."
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.md LICENSE .formatter.exs)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      extras: ["README.md", "LICENSE"]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:ash, "~> 3.33"},
      {:ash_ai, github: "sephianl/ash_ai", ref: "0ea0932f86d05669f9f58c119e6a36d7f1c38e9a"},
      {:plug, "~> 1.17"},
      {:jason, "~> 1.4"},
      {:hammer, "~> 7.5"},
      {:remote_ip, "~> 1.2"},
      # Test router only; not only: :test, which Mix refuses since ash_json_api needs phoenix in every env.
      {:phoenix, "~> 1.7", optional: true},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:styler, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:dialyxir, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:simple_sat, ">= 0.0.0", only: [:dev, :test]},
      {:sourceror, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
