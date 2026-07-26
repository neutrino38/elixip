# Example scenario driving the HTTP.Session mixin: before placing a call, the
# scenario queries a provisioning backend over HTTP and only proceeds if it
# answers 200 OK. Run it with:
#     elixipp scenarios/http_get_example.exs
#     mix scenario scenarios/http_get_example.exs
defmodule HTTP.GetExample do
  use SIP.Scenario
  # Pull in the http_GET/3 macro. `use SIP.Scenario` already brought in the
  # SIP.Context macros it relies on.
  use HTTP.Session

  config(
    username: "1000",
    authusername: "1000",
    displayname: "Test User",
    domain: "example.com",
    passwd: "changeme"
  )

  # -------------------------------------------------------------------------------
  state initial_state do
    # Fire the HTTP request; the scenario is NOT blocked — it moves on to
    # `query_backend` and waits for the tagged reply there.
    http_GET("https://backend.example.com/api/provisioning/1000", 10_000, :provisioning)
    goto(query_backend)
  end

  # -------------------------------------------------------------------------------
  state query_backend do
    # Thanks to the http_GET timeout guarantee, no `after` is needed here: a
    # timeout arrives as an {:error, :timeout} event like any other outcome.
    on_events do
      {:provisioning, {:ok, %Req.Response{status: 200, body: body}}} ->
        appdata_set(:provisioning, body)
        goto(connect_media, "backend 200 OK")

      {:provisioning, {:ok, %Req.Response{status: code}}} ->
        scenario_failure("backend HTTP #{code}")

      {:provisioning, {:error, :timeout}} ->
        scenario_failure("backend timeout")

      {:provisioning, {:error, reason}} ->
        scenario_failure("backend error: #{inspect(reason)}")
    end
  end

  # -------------------------------------------------------------------------------
  state connect_media do
    media_connect()
    goto(calling)
  end

  # -------------------------------------------------------------------------------
  state calling do
    send_INVITE("sip:90901@#{sip_ctx.domain}", :mediaserver, timeout: 90, webrtc: :no)
    goto(call_progress)
  end

  # -------------------------------------------------------------------------------
  state call_progress do
    on_events do
      {code, _rsp, _trans_pid, _dialog_pid} when code in 100..199 ->
        goto(loop, "provisional #{code}")

      {200, rsp_200, trans_pid, _dialog_pid} ->
        process_invite_reply(rsp_200, trans_pid)
        scenario_success("200 OK")

      {code, _rsp, _trans_pid, _dialog_pid} when code in 400..699 ->
        scenario_failure("Call failure with code #{code}")
    after
      30_000 -> scenario_failure("Call not answered after 30s")
    end
  end
end
