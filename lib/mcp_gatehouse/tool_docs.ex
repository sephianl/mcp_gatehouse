defmodule McpGatehouse.ToolDocs do
  @moduledoc """
  The paragraphs every MCP tool description repeats, and the page cap they
  describe.

  The cap lives here rather than as a literal beside each `pagination` block so
  that the number a read action enforces and the number its description promises
  to the model cannot drift apart — a model told it may ask for 250 and then
  refused at 100 has no way to recover.

  The wording describes the behaviour of the pinned `ash_ai` fork (keyset pages,
  oversized limits refused, `group_by` scan limit), so a bump of that fork means
  re-reading this text.
  """

  @page_cap 250
  @grouped_scan_limit "25,000"

  @doc "The largest page any MCP read tool will return, and what its actions cap at."
  @spec page_cap() :: pos_integer()
  def page_cap, do: @page_cap

  @doc "How a model should page through a large result set."
  @spec paging() :: String.t()
  def paging do
    """
    Records come back as a page: `results`, plus `has_more` saying whether another page
    exists. At most #{@page_cap} records come back per call. A larger `limit` is refused with
    an error naming the cap rather than quietly trimmed, so page with `limit: #{@page_cap}`
    and, while `has_more` is true, pass the page's `end_keyset` as `after`.\
    """
  end

  @doc """
  How a model should ask a per-group question instead of paging every record.

  `groups` names the groupings that make sense for the tool at hand, since what
  is worth grouping by differs per resource.
  """
  @spec grouping(String.t()) :: String.t()
  def grouping(groups) do
    """
    For a per-group question — #{groups} — pass `group_by` with a
    `count` or aggregate `result_type` and let the server fold, rather than paging every
    record back to count it here. Filter first: grouping streams every matching record
    and refuses past #{@grouped_scan_limit}.\
    """
  end
end
