defmodule Kelix.Mod.SiloMemoryStoreTest do
  @moduledoc "The store contract on the in-memory store the rest of the suite runs on."
  use ExUnit.Case, async: true
  use Kelix.Test.SiloStoreContract

  setup do
    {:ok, pid} = Kelix.Test.SiloMemoryStore.start_link()
    %{store: Kelix.Test.SiloMemoryStore, handle: pid}
  end
end
