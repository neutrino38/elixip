defmodule Kelix.Mod.Captioning.Token do
  @moduledoc """
  One `POST /control/token` to the speech-server's control API, for the `comp`
  function (speech-server 1.18.0 / 1.19.1, `docs/SPEECH-SERVER.md` §7.1).

      POST /control/token
      {"function": "comp", "ttl": 60, "account": "visioassistance.net"}

  The request carries those fields and nothing else: the server refuses an
  unknown one. `account` is optional, and left out when the script gives none. Only a `201` whose `token` is a non-empty base64url string and
  whose `function` is `comp` is a token — the token goes as it is into the path
  of the URL handed to the client. Its length is the server's business, not a
  contract, and is not checked.

  Bounded as a whole by `timeout_ms`, connection included: the caller is a call
  whose relay is paused while this runs.
  """

  require Logger

  @type error ::
          :timeout | :down | :invalid_response | {:speech, pos_integer, String.t() | nil}

  @doc """
  Ask `control_url` for a token. `cfg` carries `ttl` and `timeout_ms`; `account`
  is the label the speech-server bills it to, or nil.
  """
  @spec request(String.t(), map, String.t() | nil) :: {:ok, String.t()} | {:error, error}
  def request(control_url, cfg, account) do
    url = String.trim_trailing(control_url, "/") <> "/control/token"
    payload = %{"function" => "comp", "ttl" => cfg.ttl}
    payload = if account, do: Map.put(payload, "account", account), else: payload

    task =
      Task.async(fn ->
        try do
          Req.post(url,
            json: payload,
            decode_body: false,
            retry: false,
            redirect: false,
            receive_timeout: cfg.timeout_ms,
            connect_options: [timeout: cfg.timeout_ms]
          )
        rescue
          e -> {:error, e}
        catch
          kind, reason -> {:error, {kind, reason}}
        end
      end)

    case Task.yield(task, cfg.timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, {:ok, %Req.Response{status: 201, body: body}}} -> read_token(body)
      {:ok, {:ok, %Req.Response{status: status, body: body}}} -> refused(status, body)
      {:ok, {:error, %Req.TransportError{reason: :timeout}}} -> {:error, :timeout}
      {:ok, {:error, _reason}} -> {:error, :down}
      nil -> {:error, :timeout}
    end
  end

  # Never logged: the body of a 201 IS the token.
  defp read_token(body) do
    with {:ok, %{"token" => token, "function" => "comp"}} when is_binary(token) <-
           Jason.decode(body),
         true <- token =~ ~r/\A[A-Za-z0-9_-]+\z/ do
      {:ok, token}
    else
      _ -> {:error, :invalid_response}
    end
  end

  defp refused(status, body) do
    reason =
      case Jason.decode(body || "") do
        {:ok, %{"error" => reason}} when is_binary(reason) -> reason
        _ -> nil
      end

    {:error, {:speech, status, reason}}
  end
end
