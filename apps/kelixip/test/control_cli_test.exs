defmodule Kelix.Control.CLITest do
  # kelictl arg parsing + rendering (design §10.2). run/2 targets node() so it
  # dispatches locally (apply Kelix.Control) — no distribution needed in tests.
  use ExUnit.Case, async: false

  alias Kelix.Control.CLI

  defp run(argv), do: CLI.run(argv, node())

  test "status renders key lines, exit 0" do
    {0, out} = run(["status"])
    assert out =~ "node:"
    assert out =~ "active calls:"
    assert out =~ "media pool:"
  end

  test "registration list with no domain served" do
    {0, out} = run(["registration", "list"])
    assert out == "no domain served"
  end

  describe "registration list / show / remove" do
    @reg_domains """
    [[domain]]
    name = "cli.reg.example.com"

    [[domain]]
    name = "cli.empty.example.net"
    """

    # the registrar is a loadable module: a fake exporting `all/1` + `remove/3` is
    # the whole contract the core uses (see Kelix.ControlTest for the same trick)
    defmodule FakeRegistrar do
      @uri %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "10.0.0.9", port: 5062}

      def all("cli.reg.example.com") do
        %{
          "bob" => [
            %{
              contact: @uri,
              expires_at: Application.get_env(:kelixip, :fake_reg_expires_at),
              received: {"udp", {192, 168, 1, 4}, 45_112},
              flow_module: SIP.Transport.UDP,
              instance: "<urn:uuid:f81d4fae>",
              reg_id: "1",
              methods: nil
            }
          ]
        }
      end

      def all(_domain), do: %{}

      def remove(_domain, "bob", _contact), do: :ok
      def remove(_domain, _aor, _contact), do: :notfound
    end

    setup do
      Kelix.Test.Fixtures.serve_domains(@reg_domains)
      Kelix.Test.Fixtures.with_module("registrar", FakeRegistrar)
      Application.put_env(:kelixip, :fake_reg_expires_at, DateTime.add(DateTime.utc_now(), 340))
      on_exit(fn -> Application.delete_env(:kelixip, :fake_reg_expires_at) end)

      :ok
    end

    test "registration list renders one section per served domain" do
      {0, out} = run(["registration", "list"])

      assert out =~ "cli.reg.example.com\n  aor  contacts  expires  bindings"
      assert out =~ ~r/bob\s+1\s+5m\d+s\s+sip:bob@10\.0\.0\.9:5062/
      # served, nobody registered — which is not the same thing as not served
      assert out =~ "cli.empty.example.net\n  (no registration)"
    end

    test "registration list <domain> renders that domain only" do
      assert {0, out} = run(["registration", "list", "cli.reg.example.com"])
      assert out =~ "bob"
      refute out =~ "cli.empty.example.net"

      assert {1, "no such domain"} = run(["registration", "list", "ghost.example.org"])
    end

    test "registration show details each binding" do
      {0, out} = run(["registration", "show", "cli.reg.example.com", "bob"])

      assert out =~ "aor:          bob@cli.reg.example.com"
      assert out =~ "contacts:     1"
      assert out =~ "1. sip:bob@10.0.0.9:5062"
      assert out =~ ~r/expires:   in 5m\d+s \(20/
      # where the REGISTER came from, which behind a NAT the contact URI does not say
      assert out =~ "source:    udp 192.168.1.4:45112"
      assert out =~ "transport: udp"
      assert out =~ "instance:  <urn:uuid:f81d4fae>"
      assert out =~ "reg-id:    1"
      # the handset sent no `methods` param: no line rather than a dash
      refute out =~ "methods:"
    end

    test "registration show on an unregistered AOR → exit 1" do
      assert {1, "no such registration"} =
               run(["registration", "show", "cli.reg.example.com", "x"])

      assert {1, "no such registration"} =
               run(["registration", "show", "ghost.example.org", "bob"])
    end

    test "registration remove drops the AOR, or reports not found" do
      assert {0, "ok"} = run(["registration", "remove", "cli.reg.example.com", "bob"])

      assert {0, "ok"} =
               run([
                 "registration",
                 "remove",
                 "cli.reg.example.com",
                 "bob",
                 "sip:bob@10.0.0.9:5062"
               ])

      assert {1, "not found"} = run(["registration", "remove", "cli.reg.example.com", "ghost"])
      assert {1, "not found"} = run(["registration", "remove", "ghost.example.org", "bob"])
    end

    test "a mistyped registration sub-command gets the registration usage" do
      {2, out} = run(["registration", "shwo", "bob"])
      assert out =~ "usage: kelictl registration list [domain] | registration show <domain> <aor>"
    end
  end

  describe "domain list / domain show" do
    @domains_toml """
    [[domain]]
    name = "cli.example.com"
    aliases = ["cli.example.fr"]
    max_calls = 500

    [domain.registrar]
    script = "registrar-example.exs"
    default_expires = 3600

    [[domain.call]]
    pattern = "0[1-9]XXXXXXXX"
    script = "user2pstn.exs"

    [[domain.call]]
    default = true
    script = "catchall.exs"
    """

    setup do
      Kelix.Test.Fixtures.serve_domains(@domains_toml)
      :ok
    end

    test "domain list renders one row per domain" do
      {0, out} = run(["domain", "list"])

      assert out =~ ~r/domain\s+aliases\s+functions\s+calls\s+regs\s+max/
      assert out =~ ~r/cli\.example\.com\s+cli\.example\.fr\s+registrar, calls\s+0\s+0\s+500/
    end

    test "domain show renders the properties and the numbered dial-plan" do
      {0, out} = run(["domain", "show", "cli.example.com"])

      assert out =~ "domain:        cli.example.com"
      assert out =~ "aliases:       cli.example.fr"
      assert out =~ "max calls:     500"
      assert out =~ "registrar:     default_expires=3600 script=registrar-example.exs"
      assert out =~ "presence:      (disabled)"
      # first-match-wins, so the position is part of the answer
      assert out =~ "1. 0[1-9]XXXXXXXX -> user2pstn.exs"
      assert out =~ "2. (default)      -> catchall.exs"
    end

    test "an unloaded script says so rather than showing a blank module" do
      {0, out} = run(["domain", "show", "cli.example.com"])
      assert out =~ "user2pstn.exs  [not loaded]"
    end

    test "domain show accepts an alias" do
      {0, out} = run(["domain", "show", "cli.example.fr"])
      assert out =~ "domain:        cli.example.com"
    end

    test "domain show on an unknown domain → exit 1" do
      assert {1, "no such domain"} = run(["domain", "show", "ghost.example.org"])
    end

    test "a mistyped domain sub-command gets the domain usage, not `unknown module`" do
      {2, out} = run(["domain", "shwo", "x"])
      assert out =~ "usage: kelictl domain list | domain show <domain> | domain reload-all"
    end
  end

  # The script name is what the operator configured; the module is what the BEAM
  # runs, and only the script's own `defmodule` relates the two. `show` prints both,
  # plus whether the module still matches the file.
  describe "domain show — the module behind each script" do
    setup do
      mod = "KelixTest.CLIShow#{System.unique_integer([:positive])}"

      # the script lives in the fixture's own directory, so the teardown's rm_rf
      # takes it away with the config instead of enumerating files
      %{dir: dir} = Kelix.Test.Fixtures.domains_dir()
      script = Path.join(dir, "scenario.exs")

      File.write!(script, """
      defmodule #{mod} do
        use SIP.Scenario
        uas :invite
        state initial_state do
          scenario_success("ok")
        end
        on_shutdown do
          scenario_aborted("shutdown")
        end
      end
      """)

      toml = Path.join(dir, "domains.toml")

      File.write!(toml, """
      [[domain]]
      name = "cli.show.example.com"

      [[domain.call]]
      pattern = "1XXX"
      script = "#{script}"
      """)

      assert :ok = Kelix.Domains.reload(toml)
      assert {:ok, _} = Kelix.ScriptRegistry.current(script)

      %{mod: mod, script: script}
    end

    test "a loaded script shows its module and version, with no staleness marker", %{mod: mod} do
      {0, out} = run(["domain", "show", "cli.show.example.com"])
      # the `.V1` suffix IS the version — the registry compiles each load under it
      assert out =~ "[#{mod}.V1]"
      refute out =~ "file changed"
    end

    test "editing the file on disk is reported, without reloading anything", %{script: script} do
      File.write!(script, File.read!(script) |> String.replace(~s("ok"), ~s("edited")))

      {0, out} = run(["domain", "show", "cli.show.example.com"])
      assert out =~ "— file changed since load"
    end

    test "a deleted file is reported as missing", %{script: script} do
      File.rm!(script)

      {0, out} = run(["domain", "show", "cli.show.example.com"])
      assert out =~ "— file missing"
    end
  end

  describe "mediaserver list / show / enable / disable" do
    @pool [
      %{name: "mcu1", module: :mockup, url: "http://10.0.0.1:8080", enabled: true},
      %{name: "mcu2", module: :mendooze, url: "http://10.0.0.2:8080", enabled: true}
    ]

    setup do
      # Control reads the Kelix.MediaPool singleton by name: stand a populated one
      # in the place of the app's (empty) one for the duration of the test.
      :ok = Supervisor.terminate_child(Kelix.Supervisor, Kelix.MediaPool)
      on_exit(fn -> Supervisor.restart_child(Kelix.Supervisor, Kelix.MediaPool) end)

      start_supervised!(
        {Kelix.MediaPool,
         pool: @pool, probe: fn e -> e.name == "mcu1" end, first_check_ms: 60_000}
      )

      :ok = Kelix.MediaPool.check_health()
      :ok
    end

    test "mediaserver list renders one row per pool entry" do
      {0, out} = run(["mediaserver", "list"])

      assert out =~ ~r/server\s+adapter\s+url\s+enabled\s+health\s+modules/
      assert out =~ ~r|mcu1\s+mockup\s+http://10\.0\.0\.1:8080\s+on\s+up|
      assert out =~ ~r|mcu2\s+mendooze\s+http://10\.0\.0\.2:8080\s+on\s+down|
    end

    test "mediaserver show renders the entry and names whose health it is" do
      {0, out} = run(["mediaserver", "show", "mcu1"])

      assert out =~ "media server: mcu1"
      assert out =~ "adapter:      mockup"
      assert out =~ "url:          http://10.0.0.1:8080"
      assert out =~ "enabled:      on"
      assert out =~ "health:       up (pool probe)"
    end

    test "mediaserver enable / disable flips the entry, and `list` shows it" do
      assert {0, "ok"} = run(["mediaserver", "disable", "mcu1"])
      assert {0, out} = run(["mediaserver", "list"])
      assert out =~ ~r/mcu1\s+mockup\s+\S+\s+off\s+up/

      assert {0, "ok"} = run(["mediaserver", "enable", "mcu1"])
      assert {0, out} = run(["mediaserver", "list"])
      assert out =~ ~r/mcu1\s+mockup\s+\S+\s+on\s+up/
    end

    test "mediaserver show / disable on an unknown server → exit 1" do
      assert {1, "no such media server"} = run(["mediaserver", "show", "ghost"])
      assert {1, out} = run(["mediaserver", "disable", "ghost"])
      assert out =~ "error:"
    end

    test "a mistyped mediaserver sub-command gets the mediaserver usage" do
      {2, out} = run(["mediaserver", "enabel", "mcu1"])
      assert out =~ "usage: kelictl mediaserver list | mediaserver show <name>"
    end
  end

  # the old spelling was `reload-domains`; the verb behind it is unchanged
  test "domain reload-all reaches reload_domains/0" do
    prev = Application.get_env(:kelixip, :domains_path)
    Application.delete_env(:kelixip, :domains_path)
    on_exit(fn -> if prev, do: Application.put_env(:kelixip, :domains_path, prev) end)

    {1, out} = run(["domain", "reload-all"])
    assert out =~ "no_domains_path"
  end

  # `kelictl reload-all` is what `systemctl reload kelixip` runs (through
  # Kelix.Control.CLI.reload_main/0), so this rendering is also what lands in the journal.
  test "reload-all reports every stage, and exits non-zero when it was rejected" do
    %{dir: dir} = Kelix.Test.Fixtures.domains_dir()
    path = Path.join(dir, "domains.toml")
    prev = Application.get_env(:kelixip, :domains_path)
    Application.put_env(:kelixip, :domains_path, path)

    on_exit(fn ->
      if prev,
        do: Application.put_env(:kelixip, :domains_path, prev),
        else: Application.delete_env(:kelixip, :domains_path)
    end)

    File.write!(path, """
    [[domain]]
    name = "cliall.example.com"

    [domain.registrar]
    script = "#{Path.join(__DIR__, "support/scripts/valid_registrar.exs")}"
    """)

    {0, out} = run(["reload-all"])
    assert out =~ ~r/^domains\.toml:\s+reloaded \(v\d+\)$/m
    assert out =~ ~r/^scripts:\s+/m
    assert out =~ ~r/^modules:\s+/m

    # a script the node refuses: the reload is rejected, and the exit code says so —
    # which is what makes `systemctl reload` fail instead of answering "ok"
    File.write!(path, """
    [[domain]]
    name = "cliall.example.com"

    [domain.registrar]
    script = "#{Path.join(__DIR__, "support/scripts/no_shutdown.exs")}"
    """)

    {1, out} = run(["reload-all"])
    assert out =~ "REJECTED"
    assert out =~ "cooperative shutdown"
    # the config that was running is still the one running
    assert Kelix.Domains.lookup(Kelix.Domains.current(), "cliall.example.com")
  end

  # The point of the reload's script check is that the operator reads it *here*,
  # instead of on the first call routed to that domain.
  test "domain reload-all refuses a config whose script is not servable, and says which" do
    # written but not reloaded: the refusal is the subject, so `reload-all` loads it
    %{path: path} =
      Kelix.Test.Fixtures.write_domains("""
      [[domain]]
      name = "cli.example.com"

      [domain.registrar]
      script = "#{Path.join(__DIR__, "support/scripts/no_shutdown.exs")}"
      """)

    prev = Application.get_env(:kelixip, :domains_path)
    Application.put_env(:kelixip, :domains_path, path)

    on_exit(fn ->
      if prev,
        do: Application.put_env(:kelixip, :domains_path, prev),
        else: Application.delete_env(:kelixip, :domains_path)
    end)

    {1, out} = run(["domain", "reload-all"])
    assert out =~ "1 script(s) rejected"
    assert out =~ "domain cli.example.com [domain.registrar]"
    assert out =~ "cooperative shutdown"
    # printed as written, not inspect-escaped into one quoted line
    assert out =~ "\n  - "
    refute Kelix.Domains.lookup(Kelix.Domains.current(), "cli.example.com")
  end

  test "mediaserver list with an empty pool" do
    assert {0, "no media server in the pool"} = run(["mediaserver", "list"])
  end

  # The Kelix.Domains singleton is shared with the rest of the suite, so empty it
  # here rather than assuming the boot state survived the files before this one.
  test "domain list with no domain served" do
    Kelix.Test.Fixtures.serve_domains("")

    assert {0, "no domain served"} = run(["domain", "list"])
  end

  test "an unknown command prints usage, exit 2" do
    {2, out} = run(["frobnicate"])
    assert out =~ "usage: kelictl"
  end

  # The two columns an operator reads to know WHAT is running and FOR WHOM: the
  # script domains.toml routed to (the pool always knows it) and the account. A UAS
  # instance has no account of its own, so it shows the identity the inbound request
  # asserts (SIP.Msg.Ops.asserted_username/1 — P-Asserted-Identity here) until the
  # script names a better one (an AOR, a conference DID) with note_account/1.
  test "monitor names the running script and the identity the instance serves" do
    waiter = Path.join(__DIR__, "support/scripts/waiter.exs")
    route = %{domain: "cli.mon.example.com", function: :registrar, script: waiter, max_calls: nil}

    req = %{
      "P-Asserted-Identity" => "<sip:900012345@cli.mon.example.com>",
      method: :REGISTER,
      from: "\"Someone\" <sip:anonymous@anonymous.invalid>;tag=x"
    }

    assert {:accept, pid} = Kelix.InstancePool.accept(route, nil, req)
    on_exit(fn -> send(pid, {:scenario_ctl, :shutdown, :test}) end)

    # the FSM store is fed by casts: wait for the initial_state report to land
    out =
      Enum.reduce_while(1..50, "", fn _i, _acc ->
        {0, out} = run(["monitor"])
        if out =~ "900012345", do: {:halt, out}, else: Process.sleep(20) && {:cont, out}
      end)

    assert out =~ "script"
    assert out =~ "waiter.exs"
    assert out =~ "900012345"

    # And the three call-shape columns, which this instance has nothing to put in:
    # a registrar negotiates no media, connects to no media server and dials
    # nobody. They carry a standing value rather than a dash — "does not apply"
    # is an answer, "no value yet" is not the same one.
    assert out =~ ~r/medias\s+mediaserver\s+outbound/
    assert out =~ ~r/n\/a\s+none\s+n\/a/
  end

  # `continuous` swaps the one-shot snapshot for `Kelix.Control.subscribe_monitor/1`'s
  # push feed (docs/design/kelixip_liveview.md): capture_io with `""` as stdin makes
  # `IO.read/2` answer `:eof` immediately, standing in for an operator's Ctrl+D.
  describe "monitor continuous" do
    test "prints the live header and the snapshot, then stops on stdin EOF" do
      out =
        ExUnit.CaptureIO.capture_io("", fn ->
          send(self(), {:ran, run(["monitor", "continuous"])})
        end)

      assert_received {:ran, {0, "monitor stopped"}}
      assert out =~ "kelictl monitor — live, Ctrl+D to stop"
      assert out =~ "no scenario in progress"
    end

    # Sent to our own mailbox before `run/2` is even called, so it is queued ahead
    # of the reader's `{:monitor_stdin, :eof}` (sent by a process that does not
    # exist yet) — no timing race, `receive` serves its mailbox in arrival order.
    test "an upsert pushed before EOF is drawn before the loop stops" do
      row = %{
        id: 42,
        domain: "live.example.com",
        function: :calls,
        script: "x.exs",
        account: "bob",
        state: "in_call",
        event: "INVITE",
        command: "-",
        medias: "AV",
        mediaserver: "mcu1",
        outbound: "sip:x@1.2.3.4"
      }

      send(self(), {:kelix_monitor, {:upsert, row}})

      out =
        ExUnit.CaptureIO.capture_io("", fn ->
          send(self(), {:ran, run(["monitor", "continuous"])})
        end)

      assert_received {:ran, {0, "monitor stopped"}}
      assert out =~ "live.example.com"
      assert out =~ "in_call"
    end

    test "monitor completes to continuous" do
      assert {0, out} = run(["complete", "monitor", ""])
      assert String.split(out, "\n", trim: true) == ["continuous"]
    end

    test "usage lists it" do
      {0, out} = run(["help"])
      assert out =~ "monitor continuous"
    end
  end

  test "stop with a non-integer id → error, exit 2" do
    {2, out} = run(["stop", "abc"])
    assert out =~ "must be an integer"
  end

  test "stop with an unknown id → error, exit 1" do
    {1, out} = run(["stop", "999999"])
    assert out =~ "error:"
  end

  # `mcu` is a module name, not a core noun: the enable/disable of a pool entry
  # moved to `mediaserver …`, so `mcu …` is now the module's own namespace.
  test "mcu <name> on|off is gone — it lands on the module dispatch" do
    {1, out} = run(["mcu", "ghost", "off"])
    assert out =~ ~s(is neither a kelictl command nor a loaded module)
  end

  test "log-level valid → ok" do
    prev = Logger.level()
    on_exit(fn -> Logger.configure(level: prev) end)
    assert {0, "ok"} = run(["log-level", "info"])
  end

  test "reload-script with no name → usage error, exit 2" do
    {2, out} = run(["reload-script"])
    assert out =~ "at least one script name"
  end

  test "reload-script reports per-name results" do
    {code, out} = run(["reload-script", "nope"])
    assert code == 1
    assert out =~ "nope:"
  end

  test "a module command on an unknown module → error, exit 1" do
    {1, out} = run(["mymod", "docmd", "arg"])
    assert out =~ "error:"
  end

  # FW-5 (docs/design/DESIGN-KELIXIP.md#7-the-module-system): the last CLI/REST parity gap was
  # discovery — a module's command set existed only in its source. Both listings are
  # rendered from `describe_control/0` + `describe/0`, so a module gets its usage
  # without writing one.
  describe "module list / <module> help — discovery" do
    defmodule HelpCtl do
      def describe(), do: %{version: "2.1.0", exports: [{:admit, 2}, {:leave, 2}]}

      def describe_control() do
        [
          %{
            name: "conference.create",
            rest: {:post, "/conferences"},
            status: 201,
            errors: %{did_in_use: 400},
            rw: :w,
            args: [
              %{name: "domain", required: true},
              %{name: "name", required: false},
              # an argument whose value has a vocabulary of its own carries it: the
              # CLI prints it without knowing what a mosaic is (§8.3.7)
              %{
                name: "layout",
                required: false,
                help: ["a mosaic and/or a size, in any order", "mosaic: 1x1 2x2", "size: cif vga"]
              },
              %{name: "vad", required: false, help: "none | basic | full"}
            ],
            help: "Create a conference"
          },
          %{
            name: "conference.update",
            rest: {[:put, :patch], "/conferences/:uid"},
            rw: :w,
            args: [%{name: "uid", required: true}],
            help: "Update a conference"
          }
        ]
      end

      def handle_control(cmd, args), do: {:ok, %{cmd: cmd, args: args}}
    end

    # A module with no control surface at all: it must still be listed (it is loaded,
    # and its facades are callable), with an empty command set rather than an absence.
    defmodule SilentCtl do
      def describe(), do: %{version: "0.1.0", exports: []}
    end

    setup do
      Kelix.Test.Fixtures.with_module("helpmod", HelpCtl)
      Kelix.Test.Fixtures.with_module("silentmod", SilentCtl)
      :ok = Kelix.Control.Registry.register("helpmod", HelpCtl.describe_control())

      on_exit(fn -> Kelix.Control.Registry.deregister("helpmod") end)
    end

    test "module list shows one row per loaded module, with its counts" do
      {0, out} = run(["module", "list"])
      assert out =~ ~r/helpmod\s+2\.1\.0\s+Kelix\.Control\.CLITest\.HelpCtl\s+2\s+2/
      assert out =~ ~r/silentmod\s+0\.1\.0\s+\S+\s+0\s+0/
      assert out =~ "kelictl <module> help"
    end

    test "<module> help renders the commands, their route and their args" do
      {0, out} = run(["helpmod", "help"])

      assert out =~ "helpmod 2.1.0 (Kelix.Control.CLITest.HelpCtl)"
      assert out =~ "conference.create  [POST /modules/helpmod/conferences]"
      # required args are starred, so the calling convention is readable at a glance
      assert out =~ "args: domain* name layout vad"
      assert out =~ "Create a conference"
      # an argument's own help, its continuation lines aligned under it
      assert out =~ "      layout: a mosaic and/or a size, in any order\n"
      assert out =~ "\n              mosaic: 1x1 2x2\n"
      # one line or a list, both declared the same way
      assert out =~ "      vad: none | basic | full"
      # a method list stays a method list: one declaration, two verbs
      assert out =~ "conference.update  [PUT|PATCH /modules/helpmod/conferences/:uid]"
      assert out =~ "facades (import Kelix.Control.CLITest.HelpCtl):"
      assert out =~ "admit/2, leave/2"
    end

    test "<module> help <cmd> narrows it to one command, keeping the arg help" do
      {0, out} = run(["helpmod", "help", "conference.create"])

      assert out =~ "conference.create  [POST /modules/helpmod/conferences]"
      assert out =~ "layout: a mosaic and/or a size"
      # …and nothing of the other commands
      refute out =~ "conference.update"
      refute out =~ "facades"
    end

    test "<module> help <cmd> on a command the module does not declare → exit 2" do
      {2, out} = run(["helpmod", "help", "conference.explode"])
      assert out =~ ~s(declares no command "conference.explode")
      assert out =~ "kelictl helpmod help"
    end

    test "<module> help on a module with no control surface says so" do
      {0, out} = run(["silentmod", "help"])
      assert out =~ "commands: none"
    end

    test "help on an unknown module → error, exit 1" do
      {1, out} = run(["ghostmod", "help"])
      assert out =~ ~s(no module named "ghostmod")
    end

    test "a declared command still dispatches (help shadows nothing else)" do
      {0, out} = run(["helpmod", "conference.create", "domain=example.com"])
      assert out =~ "example.com"
    end

    # The `bin/kelictl` overlay runs the CLI inside the node through `kelixip rpc`,
    # and it used to join argv into one string for the CLI to re-split — which lost
    # the shell's quoting: a value with a space became two arguments, and the JSON
    # forms the docs show (`muted='{"audio":true}'`) lost their inner quotes. The
    # overlay now passes a list, so what the operator quoted arrives intact.
    test "rpc_main/1 takes argv as a list, keeping spaces and inner quotes" do
      out =
        ExUnit.CaptureIO.capture_io(fn ->
          CLI.rpc_main([
            "helpmod",
            "conference.create",
            "name=Sales weekly",
            ~s(muted={"audio":true})
          ])
        end)

      # the tokens reach the module whole — the space survived, and so did the quotes
      # the JSON needs (this fake echoes its raw args; a real module decodes them)
      assert out =~ ~s("name=Sales weekly")
      assert out =~ ~S(muted={\"audio\":true})
    end

    test "rpc_main/1 still accepts the string form an older overlay sends" do
      out =
        ExUnit.CaptureIO.capture_io(fn ->
          CLI.rpc_main("helpmod conference.create domain=example.com")
        end)

      assert out =~ "example.com"
    end
  end

  test "module with a bad sub-command prints the module usage, exit 2" do
    {2, out} = run(["module", "frobnicate"])
    assert out =~ "usage: kelictl module list"
  end

  # A command may declare its own rendering (`render:` in describe_control/0):
  # the CLI formats what the module declared — a table for a list, a labelled
  # detail view for a map — and stays module-agnostic doing so.
  describe "module command rendering — render: hints" do
    defmodule RenderCtl do
      def describe(), do: %{version: "1.0.0", exports: []}

      def describe_control() do
        [
          %{
            name: "thing.list",
            rest: {:get, "/things"},
            rw: :r,
            args: [],
            render: %{kind: :table, columns: ~w(name domain created_at)},
            help: "List the things"
          },
          %{
            name: "thing.show",
            rest: {:get, "/things/:uid"},
            rw: :r,
            args: [%{name: "uid", required: true}],
            render: %{
              kind: :detail,
              fields: ~w(name domain video layout members medias),
              labels: %{
                "video.size" => %{"6" => "hd720p"},
                "layout.comp" => %{"0" => "1x1"},
                # a dotted path reaches a column of a *nested* table too
                "members.state" => %{"ringing" => "alerting"}
              },
              nested: %{"members" => %{columns: ~w(id name state)}}
            },
            help: "Show one thing"
          },
          %{
            name: "thing.derived",
            rest: {:get, "/things/derived"},
            rw: :r,
            args: [],
            render: %{kind: :detail, fields: ~w(members)},
            help: "A detail view that declares no columns for its nested list"
          },
          %{
            name: "thing.raw",
            rest: {:get, "/things/raw"},
            rw: :r,
            args: [],
            help: "A command with no render hint"
          }
        ]
      end

      def handle_control("thing.list", %{"args" => ["empty"]}), do: {:ok, []}

      def handle_control("thing.list", _args) do
        {:ok,
         [
           %{
             name: "test",
             domain: "example.com",
             created_at: ~U[2026-08-03 09:59:39.005163Z],
             video: %{size: 6}
           },
           %{name: "other", domain: nil, created_at: nil}
         ]}
      end

      def handle_control("thing.show", _args) do
        {:ok,
         %{
           name: "test",
           domain: "example.com",
           video: %{size: 6, fps: 15},
           layout: %{comp: 0, auto: true},
           codecs: %{audio: ["OPUS", "PCMA"]},
           members: [
             %{id: 1, name: "alice", state: :connected},
             %{id: 2, name: "bob", state: :ringing}
           ],
           # a map keyed by data, whose values are maps: one line per key
           medias: %{
             audio: %{codec: "PCMA", send: {"10.0.0.9", 40_000}},
             video: %{codec: "H264", send: {"10.0.0.9", 40_002}}
           },
           stale: false
         }}
      end

      def handle_control("thing.derived", _args),
        do: {:ok, %{members: [%{name: "alice", state: :connected}]}}

      def handle_control("thing.raw", _args), do: {:ok, %{name: "raw"}}
    end

    setup do
      Kelix.Test.Fixtures.with_module("rmod", RenderCtl)
      :ok = Kelix.Control.Registry.register("rmod", RenderCtl.describe_control())
      on_exit(fn -> Kelix.Control.Registry.deregister("rmod") end)
    end

    test "a :table hint renders the declared columns, in order, nil as a dash" do
      {0, out} = run(["rmod", "thing.list"])
      [header, row1, row2] = String.split(out, "\n")

      assert header =~ ~r/^name\s+domain\s+created_at$/
      # microseconds are dropped, undeclared keys (video) do not become columns
      assert row1 =~ ~r/^test\s+example\.com\s+2026-08-03 09:59:39Z$/
      assert row2 =~ ~r/^other\s+-\s+-$/
    end

    test "a :table hint on an empty list says so instead of printing []" do
      assert {0, "(none)"} = run(["rmod", "thing.list", "empty"])
    end

    test "a :detail hint renders one labelled line per field, declared order first" do
      {0, out} = run(["rmod", "thing.show"])

      # declared fields lead, whatever else the result carries follows (sorted)
      assert ["Name:" <> _, "Domain:" <> _, "Video:" <> _, "Layout:" <> _, "Members:" <> _ | _] =
               String.split(out, "\n")

      # nested maps fit one line as k=v pairs, enum labels applied by dotted path
      assert out =~ ~r/Video:\s+fps=15 size=hd720p/
      assert out =~ ~r/Layout:\s+auto=true comp=1x1/
      assert out =~ ~r/Codecs:\s+audio=OPUS,PCMA/
      # what the result carries but the hint does not declare still shows up
      assert out =~ ~r/Stale:\s+false/
    end

    # A list of maps and a map of maps are the two shapes no line can hold: they were
    # what came out as an inspected term, and each now gets a block of its own.
    test "a field holding a list of maps becomes an indented table of the declared columns" do
      {0, out} = run(["rmod", "thing.show"])

      assert out =~ """
             Members:
               id  name   state
               1   alice  connected
               2   bob    alerting
             """

      # `members.state` renamed ringing → alerting: a dotted path reaches a nested
      # column exactly as it reaches a top-level field
      refute out =~ "ringing"
    end

    test "a field holding a map of maps becomes one aligned line per key" do
      {0, out} = run(["rmod", "thing.show"])

      # the key (a media name) is data, so it is a column, not a label; and an address
      # pair reads as its elements rather than as an Elixir tuple
      assert out =~ """
             Medias:
               audio  codec=PCMA send=(10.0.0.9, 40000)
               video  codec=H264 send=(10.0.0.9, 40002)
             """

      refute out =~ "%{"
    end

    test "a nested list with no declared columns derives them from the rows" do
      {0, out} = run(["rmod", "thing.derived"])

      assert out ==
               String.trim_trailing("""
               Members:
                 name   state
                 alice  connected
               """)
    end

    test "a command without a render hint keeps the raw term" do
      {0, out} = run(["rmod", "thing.raw"])
      assert out =~ "%{name: \"raw\"}"
    end
  end

  # FW-5, second half: a failed module command exits with the class the module
  # declared for that reason, so a provisioning script can branch on the exit code
  # instead of grepping the message. The classes come from the same `errors:` map the
  # REST frontal turns into HTTP statuses — one declaration, two frontals.
  describe "exit codes from a command's declared errors" do
    defmodule ExitCtl do
      def describe_control() do
        [
          %{
            name: "thing.create",
            rest: {:post, "/things"},
            status: 201,
            errors: %{taken: 409, backend_down: 503, bad_shape: 400},
            rw: :w,
            args: [],
            help: "create"
          },
          %{
            name: "thing.show",
            rest: {:get, "/things/:uid"},
            rw: :r,
            args: [%{name: "uid", required: true}],
            help: "show"
          }
        ]
      end

      def handle_control("thing.create", %{"args" => [reason]}),
        do: {:error, String.to_atom(reason)}

      def handle_control("thing.create", _args), do: {:ok, %{uid: "t-1"}}
      # a reason this command declares nothing for: the default mapping decides
      def handle_control("thing.show", _args), do: {:error, :not_found}
    end

    setup do
      Kelix.Test.Fixtures.with_module("exitmod", ExitCtl)
      :ok = Kelix.Control.Registry.register("exitmod", ExitCtl.describe_control())
      on_exit(fn -> Kelix.Control.Registry.deregister("exitmod") end)
    end

    test "a declared 409 is a conflict (4), a declared 503 unavailable (5)" do
      assert {4, out} = run(["exitmod", "thing.create", "taken"])
      assert out =~ "taken"
      assert {5, _} = run(["exitmod", "thing.create", "backend_down"])
    end

    test "a declared 400 is a bad argument (2), like a usage error" do
      assert {2, _} = run(["exitmod", "thing.create", "bad_shape"])
    end

    test "an undeclared reason keeps the default mapping: :not_found → 3" do
      assert {3, out} = run(["exitmod", "thing.show", "uid=t-9"])
      assert out =~ "not_found"
    end

    # safe_call/3's own verdicts: the service is absent or wedged, which is the
    # server's problem — a 400's "fix your request" would be exactly wrong.
    test "a wedged or absent module is unavailable (5), declared or not" do
      assert {5, _} = run(["exitmod", "thing.create", "down"])
      assert {5, _} = run(["exitmod", "thing.create", "timeout"])
    end

    test "an undeclared, unclassifiable reason stays a bad argument (2)" do
      assert {2, _} = run(["exitmod", "thing.create", "something_else"])
    end

    test "success is still 0" do
      assert {0, _} = run(["exitmod", "thing.create"])
    end

    # An unknown module is not a module verdict: it prints the usage and keeps the
    # generic 1, as it did before this mapping existed.
    test "an unknown module is unchanged (1)" do
      assert {1, out} = run(["ghostmod", "thing.create"])
      assert out =~ "is neither a kelictl command nor a loaded module"
    end

    test "a node that does not answer is unavailable (5)" do
      assert {5, out} = CLI.run(["exitmod", "thing.create"], :"ghost@127.0.0.1")
      assert out =~ "unreachable"
    end
  end

  describe "online help" do
    # Help is the one thing that must work when the node does not: an operator
    # reaching for `kelictl help` on a box whose service is down gets the text, not
    # `unreachable`. So every assertion here targets a node that cannot answer.
    defp help(argv), do: CLI.run(argv, :"ghost@127.0.0.1")

    test "the bare command, `help`, `-h` and `--help` all print the command list" do
      for argv <- [[], ["help"], ["-h"], ["--help"]] do
        assert {0, out} = help(argv)
        assert out =~ "usage: kelictl <command> [args]"
        assert out =~ "registration list [domain]"
        assert out =~ "topics: registration, domain, mediaserver, module, reload, drain"
      end
    end

    test "a topic is reachable both as `help <topic>` and as `<topic> help`" do
      for topic <- ["registration", "domain", "mediaserver", "module"] do
        assert {0, out} = help(["help", topic])
        assert {0, ^out} = help([topic, "help"])
        assert out =~ "kelictl #{topic}"
      end
    end

    test "the topics that are not core nouns are reachable as `help <topic>`" do
      for topic <- ["reload", "drain"] do
        assert {0, out} = help(["help", topic])
        assert out =~ "kelictl"
      end
    end

    test "each command in a topic carries its REST route, so both frontals read together" do
      {0, out} = help(["help", "registration"])
      assert out =~ "[GET /registrations]"
      assert out =~ "[GET /domains/<domain>/registrations/<aor>]"
      assert out =~ "[DELETE /domains/<domain>/registrations/<aor>]"
      # And what the repatriated documentation says, at the place it is now read.
      assert out =~ "unique only WITHIN a domain"
      assert out =~ "docs/kelixip/modules/registrar.md"
    end

    test "an unknown topic is a usage error listing the real ones" do
      assert {2, out} = help(["help", "registrations"])
      assert out =~ "no help topic \"registrations\""
      assert out =~ "registration, domain, mediaserver, module, reload, drain"
    end

    # `<module> help` belongs to the module namespace and still goes to the node:
    # the reserved core nouns must not have swallowed it.
    test "a module namespace still resolves its own help against the node" do
      assert {1, out} = help(["mcu", "help"])
      assert out =~ "unreachable"
    end
  end

  describe "shell completion" do
    defmodule CompRegistrar do
      @uri %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "10.0.0.9", port: 5062}

      def all("cli.comp.example.com"),
        do: %{"alice" => [%{contact: @uri, expires_at: DateTime.utc_now()}], "bob" => []}

      def all(_domain), do: %{}
    end

    defp words(argv, target \\ node()) do
      assert {0, out} = CLI.run(["complete" | argv], target)
      String.split(out, "\n", trim: true)
    end

    # A served config with a loaded call script: `reload-script` completes the names
    # the registry actually holds, which no fixture-free setup would have.
    setup do
      %{dir: dir} = Kelix.Test.Fixtures.domains_dir()
      script = Path.join(dir, "completion.exs")

      File.write!(script, """
      defmodule KelixTest.Completion#{System.unique_integer([:positive])} do
        use SIP.Scenario
        uas :invite
        state initial_state do
          scenario_success("ok")
        end
        on_shutdown do
          scenario_aborted("shutdown")
        end
      end
      """)

      toml = Path.join(dir, "domains.toml")

      File.write!(toml, """
      [[domain]]
      name = "cli.comp.example.com"

      [[domain.call]]
      pattern = "1XXX"
      script = "#{script}"

      [[domain]]
      name = "cli.other.example.net"
      """)

      assert :ok = Kelix.Domains.reload(toml)

      Kelix.Test.Fixtures.with_module("registrar", CompRegistrar)
      Kelix.Test.Fixtures.with_module("compmod", Kelix.Control.CLITest.HelpCtl)

      :ok =
        Kelix.Control.Registry.register(
          "compmod",
          Kelix.Control.CLITest.HelpCtl.describe_control()
        )

      on_exit(fn -> Kelix.Control.Registry.deregister("compmod") end)

      %{script: script}
    end

    test "the first word offers the core commands and the loaded modules" do
      candidates = words([""])

      assert "status" in candidates
      assert "reload-script" in candidates
      assert "graceful-shutdown" in candidates
      # what no shipped script could know
      assert "compmod" in candidates
      # not an operator verb: the hook is not part of the surface it completes
      refute "complete" in candidates
    end

    test "a prefix filters, and an empty answer is empty — never an error" do
      assert words(["rel"]) == ["reload-all", "reload-script"]
      assert words(["zzz"]) == []
    end

    test "a core noun offers its sub-commands, its object names, then its AORs" do
      assert words(["registration", ""]) == ["help", "list", "remove", "show"]

      assert words(["registration", "show", "cli."]) ==
               ["cli.comp.example.com", "cli.other.example.net"]

      # the AORs of the domain already typed, not of the whole location service
      assert words(["registration", "show", "cli.comp.example.com", ""]) == ["alice", "bob"]
      assert words(["registration", "show", "cli.other.example.net", ""]) == []
    end

    test "a mistyped core noun completes nothing, and is never taken for a module" do
      assert words(["domain", "shwo", ""]) == []
    end

    # Membership, not equality: the registry keeps what earlier tests loaded, and a
    # script stays reloadable after its rule is gone.
    test "reload-script offers the configured scripts and its flag", %{script: script} do
      candidates = words(["reload-script", ""])

      # configured by the served domains.toml and never called: the registry does not
      # hold it yet, and it is reloadable all the same
      assert script in candidates
      assert "--notify" in candidates

      # every word after the verb is another script name, so the flag stays offered
      assert words(["reload-script", script, "--n"]) == ["--notify"]
    end

    test "log-level offers the vocabulary Kelix.Control validates against" do
      assert words(["log-level", ""]) == Kelix.Control.log_levels()
    end

    test "a module namespace offers its declared commands, then their arguments" do
      assert words(["compmod", ""]) == ["conference.create", "conference.update", "help"]
      assert words(["compmod", "help", "conference.c"]) == ["conference.create"]

      assert words(["compmod", "conference.create", ""]) ==
               ["domain=", "layout=", "name=", "vad="]

      # an argument already given is not offered twice
      assert words(["compmod", "conference.create", "domain=x", ""]) ==
               ["layout=", "name=", "vad="]

      # the value of an argument is the module's vocabulary, not ours to guess
      assert words(["compmod", "conference.create", "layout="]) == []
    end

    # The shell reads stdout as a word list: there is no way to show it an error, so
    # an unreachable node must answer with the static half and exit 0.
    test "a node that does not answer still completes the static tree" do
      candidates = words([""], :"ghost@127.0.0.1")

      assert "status" in candidates
      refute "compmod" in candidates

      assert words(["registration", ""], :"ghost@127.0.0.1") == ["help", "list", "remove", "show"]
      assert words(["registration", "show", ""], :"ghost@127.0.0.1") == []
    end
  end
end
