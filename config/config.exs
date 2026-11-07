import Config

config :ash,
  allow_forbidden_field_for_relationships_by_default?: true,
  include_embedded_source_by_default?: false,
  show_keysets_for_all_actions?: false,
  default_page_type: :keyset,
  policies: [no_filter_static_forbidden_reads?: false],
  keep_read_action_loads_when_loading?: false,
  default_actions_require_atomic?: true,
  read_action_after_action_hooks_in_order?: true,
  bulk_actions_default_to_errors?: true,
  transaction_rollback_on_error?: true,
  default_string_length_count: :codepoints

if config_env() == :test do
  config :ash, :disable_async?, true

  config :logger, level: :warning

  config :mcp_gatehouse,
    ash_domains: [McpGatehouse.Tools, McpGatehouse.Test.OAuth, McpGatehouse.Test.Catalog],
    filtered_parameters: ~w(password token secret code_verifier code_challenge),
    rate_limiter: McpGatehouse.Test.RateLimiterStub
end
