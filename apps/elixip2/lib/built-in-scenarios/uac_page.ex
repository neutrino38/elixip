defmodule UAC.Page do
  @moduledoc """
  Built-in page-mode scenario (RFC 3428), compiled into the app and bundled into
  the `elixipp` escript: sends one MESSAGE, or N at an interval, and checks the
  final answer of each. Run it by module name, without a `.exs` file:

      elixipp --to sip:bob@127.0.0.1:5070 UAC.Page
      elixipp -c accounts.json --to sip:bob@example.com --count 5 --interval 500 UAC.Page
      elixipp --to sip:bob@example.com --body "code 4321" --expires 120 --expect 202 UAC.Page

  The command-line options land in the scenario's appdata, over the defaults of
  the `config` block below: `--to` (`page_to`), `--body` (`page_body`),
  `--content-type` (`page_content_type`), `--expires` (`page_expires`, the
  content's lifetime as an `Expires` header), `--count` (`page_count`),
  `--interval` in ms (`page_interval_ms`), `--expect` (`page_expect`, the code
  every page must get).

  A 401 or 407 is answered once per page with the account's credentials, as a
  node that challenges the first MESSAGE of a conversation expects.

  The editable, file-loadable copy lives in `scenarios/uac_page.exs` (module
  `UAC.PageExample`); this is the canonical bundled version.
  """
  use SIP.Scenario

  config(
    username: "1000",
    authusername: "1000",
    displayname: "Test User",
    domain: "example.com",
    passwd: "changeme",
    page_to: "sip:2000@example.com",
    page_body: "Hello from elixipp",
    page_content_type: "text/plain",
    page_expires: nil,
    page_count: 1,
    page_interval_ms: 1_000,
    page_expect: 200
  )

  state initial_state do
    appdata_set(:sent, 0)
    goto(sending)
  end

  state sending do
    appdata_set(:sent, appdata_get(:sent) + 1)
    appdata_set(:challenged, false)

    send_page(appdata_get(:page_to), appdata_get(:page_body), appdata_get(:page_content_type),
      expires: appdata_get(:page_expires)
    )

    goto(awaiting)
  end

  # `stay` on the challenge: the page sent again answers it, and the deadline
  # covers both.
  state awaiting do
    on_events do
      {:page, :answered, %{code: code, response: rsp}} when code in [401, 407] ->
        if appdata_get(:challenged) do
          scenario_failure("page #{appdata_get(:sent)} challenged twice: #{code}")
        else
          appdata_set(:challenged, true)

          send_page(
            appdata_get(:page_to),
            appdata_get(:page_body),
            appdata_get(:page_content_type),
            expires: appdata_get(:page_expires),
            auth: rsp
          )

          stay("#{code}, answering the challenge")
        end

      {:page, :answered, %{code: code}} ->
        cond do
          code != appdata_get(:page_expect) ->
            scenario_failure(
              "page #{appdata_get(:sent)} got #{code}, expected #{appdata_get(:page_expect)}"
            )

          appdata_get(:sent) < appdata_get(:page_count) ->
            goto(pause, "#{code}")

          true ->
            scenario_success("#{appdata_get(:sent)} page(s) answered #{code}")
        end

      {:page, :failed, %{reason: reason}} ->
        scenario_failure("page #{appdata_get(:sent)} not answered: #{inspect(reason)}")
    after
      40_000 -> scenario_failure("page #{appdata_get(:sent)}: no answer")
    end
  end

  state pause do
    on_events do
      _ignored -> stay("ignored")
    after
      appdata_get(:page_interval_ms) -> goto(sending, "next page")
    end
  end
end
