defmodule SIP.Test.Log do
  @moduledoc """
  Keeps the suite's log file bounded.

  `config/test.exs` sends every log line to `test.log` at the repo root instead of
  the console; the backend appends, so across runs that file grows without bound.
  A green suite has nothing to say and its log is deleted.

  A suite that failed keeps its log, under a per-app name: the umbrella runs the
  four suites in a row and does NOT stop on the first failure, so a log left under
  the shared name would be deleted by the next suite.
  """

  @doc "Call from a test_helper, after `ExUnit.start/1`."
  def setup do
    File.rm(kept_path())
    ExUnit.after_suite(&close/1)
  end

  defp close(%{failures: 0}) do
    Logger.flush()
    File.rm(path())
  end

  defp close(_) do
    Logger.flush()

    case File.rename(path(), kept_path()) do
      :ok -> IO.puts("\nLog of this suite kept in #{kept_path()}")
      _ -> :ok
    end
  end

  defp path, do: Application.get_env(:logger, :file_log)[:path]

  defp kept_path, do: Path.rootname(path()) <> "-#{Mix.Project.config()[:app]}.log"
end
