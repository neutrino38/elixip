defmodule SIP.DialogImpl.Nonce do
  @moduledoc """
  Nonce bookkeeping for digest authentication challenges (401/407) issued by
  a dialog acting as a UAS (e.g. a registrar).

  Helper module composed into `SIP.DialogImpl`: every function takes the
  dialog state struct and returns an updated one. Nonces live in the state's
  `nonce_map` (nonce => expiration time); `add/2` arms a timer that fires a
  `:check_expired_nonces` message which `SIP.DialogImpl.handle_info/2`
  delegates to `purge_expired/1`.
  """
  require Logger

  def purge_expired(state = %SIP.DialogImpl{}) do
    now = DateTime.utc_now()

    new_nonce_map =
      Enum.reduce(state.nonce_map, %{}, fn {nonce, expiration_time}, acc ->
        if DateTime.compare(now, expiration_time) == :lt do
          Map.put(acc, nonce, expiration_time)
        else
          Logger.debug(
            dialogpid: self(),
            module: __MODULE__,
            message: "Nonce #{nonce} expired and removed from nonce_map"
          )

          acc
        end
      end)

    %SIP.DialogImpl{state | nonce_map: new_nonce_map}
  end

  def add(state = %SIP.DialogImpl{}, nonce) do
    # Nonce valid for 30 seconds
    expiration_time = DateTime.utc_now() |> DateTime.add(30, :second)
    new_nonce_map = Map.put(state.nonce_map, nonce, expiration_time)
    # Arm a timer to check for expired nonces after 30 seconds
    Process.send_after(self(), :check_expired_nonces, 30100)
    %SIP.DialogImpl{state | nonce_map: new_nonce_map}
  end

  def valid?(state = %SIP.DialogImpl{}, nonce) do
    case Map.get(state.nonce_map, nonce) do
      nil ->
        Logger.info(
          dialogpid: self(),
          module: __MODULE__,
          message: "Nonce #{nonce} is invalid or expired"
        )

        false

      expiration_time ->
        if DateTime.compare(DateTime.utc_now(), expiration_time) == :lt do
          true
        else
          Logger.info(
            dialogpid: self(),
            module: __MODULE__,
            message: "Nonce #{nonce} has expired"
          )

          false
        end
    end
  end
end
