# Presence session layer (PUBLISH/SUBSCRIBE/MESSAGE/NOTIFY behaviour).
# Part of the SIP.Session namespace; see SIPSession.ex for the common core.

defmodule SIP.Session.Presence do
  @callback on_new_publish(dialog_id :: pid, pub_req :: map) :: { :accept, pid } | { :reject, integer }
  @callback on_new_subscribe(dialog_id :: pid, sub_req :: map) :: { :accept, pid } | { :reject, integer }
  @callback on_message(dialog_id :: pid, msg_req :: map) :: { :accept, pid } | { :reject, integer }
  @callback on_info(dialog_id :: pid, msg_req :: map) :: { :accept, pid } | { :reject, integer }
  @callback on_session_expired(dialog_id :: pid, app_pid :: pid) :: nil
end

