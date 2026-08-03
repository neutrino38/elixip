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
      path = Path.join(System.tmp_dir!(), "cli_regs_#{System.unique_integer([:positive])}.toml")
      File.write!(path, @reg_domains)
      assert :ok = Kelix.Domains.reload(path)
      Kelix.ModuleRegistry.register("registrar", FakeRegistrar, %{})
      Application.put_env(:kelixip, :fake_reg_expires_at, DateTime.add(DateTime.utc_now(), 340))

      on_exit(fn ->
        Application.delete_env(:kelixip, :fake_reg_expires_at)
        Kelix.ModuleRegistry.unregister("registrar")
        empty = path <> ".empty"
        File.write!(empty, "")
        Kelix.Domains.reload(empty)
        File.rm(path)
        File.rm(empty)
      end)

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
      path =
        Path.join(System.tmp_dir!(), "cli_domains_#{System.unique_integer([:positive])}.toml")

      File.write!(path, @domains_toml)
      assert :ok = Kelix.Domains.reload(path)

      on_exit(fn ->
        empty = path <> ".empty"
        File.write!(empty, "")
        Kelix.Domains.reload(empty)
        File.rm(path)
        File.rm(empty)
      end)

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

  test "mediaserver list with an empty pool" do
    assert {0, "no media server in the pool"} = run(["mediaserver", "list"])
  end

  # The Kelix.Domains singleton is shared with the rest of the suite, so empty it
  # here rather than assuming the boot state survived the files before this one.
  test "domain list with no domain served" do
    path =
      Path.join(System.tmp_dir!(), "cli_domains_empty_#{System.unique_integer([:positive])}.toml")

    File.write!(path, "")
    on_exit(fn -> File.rm(path) end)
    assert :ok = Kelix.Domains.reload(path)

    assert {0, "no domain served"} = run(["domain", "list"])
  end

  test "an unknown command prints usage, exit 2" do
    {2, out} = run(["frobnicate"])
    assert out =~ "usage: kelictl"
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

  # FW-5 (docs/design/mcu_module.md §8.3.6): the last CLI/REST parity gap was
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
            args: [%{name: "domain", required: true}, %{name: "name", required: false}],
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
      Kelix.ModuleRegistry.register("helpmod", HelpCtl, %{})
      Kelix.ModuleRegistry.register("silentmod", SilentCtl, %{})
      :ok = Kelix.Control.Registry.register("helpmod", HelpCtl.describe_control())

      on_exit(fn ->
        Kelix.ModuleRegistry.unregister("helpmod")
        Kelix.ModuleRegistry.unregister("silentmod")
        Kelix.Control.Registry.deregister("helpmod")
      end)
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
      assert out =~ "args: domain* name"
      assert out =~ "Create a conference"
      # a method list stays a method list: one declaration, two verbs
      assert out =~ "conference.update  [PUT|PATCH /modules/helpmod/conferences/:uid]"
      assert out =~ "facades (import Kelix.Control.CLITest.HelpCtl):"
      assert out =~ "admit/2, leave/2"
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
      Kelix.ModuleRegistry.register("rmod", RenderCtl, %{})
      :ok = Kelix.Control.Registry.register("rmod", RenderCtl.describe_control())

      on_exit(fn ->
        Kelix.ModuleRegistry.unregister("rmod")
        Kelix.Control.Registry.deregister("rmod")
      end)
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
      Kelix.ModuleRegistry.register("exitmod", ExitCtl, %{})
      :ok = Kelix.Control.Registry.register("exitmod", ExitCtl.describe_control())

      on_exit(fn ->
        Kelix.ModuleRegistry.unregister("exitmod")
        Kelix.Control.Registry.deregister("exitmod")
      end)
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
end
