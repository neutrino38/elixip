defmodule SIP.Scenario.Child do
  @moduledoc """
  Handle on a sub-FSM (child scenario) spawned from a parent scenario via the
  `sub_fsm` macro of `SIP.Scenario`.

  The parent keeps one handle per child in its context appdata, under the
  `:__children__` key, indexed by the local name it assigned the child (`as:`).
  The `ref` is the monitor reference returned by `spawn_monitor`, used to
  correlate the `{:DOWN, ref, …}` safety-net message when a child dies without
  having sent its `{:scenario_exit, name, …}`.
  """

  @type t :: %__MODULE__{
          name: atom(),
          pid: pid(),
          ref: reference(),
          module: module()
        }

  defstruct [:name, :pid, :ref, :module]
end
