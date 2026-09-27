# Une exception dans un état doit couper l'appel (prompt d'implémentation)

> **Corrigé le 2026-09-21**, option §6.1. Côté `:fsl` (0.2.1) :
> `FSL.Context.snapshot/1` / `latest/1` / `forget/0`, appelés par `put/3` et
> `appdata_set/3`, et les clauses `rescue` et `catch` de `state` (et de
> `on_shutdown`) relisent la photo. Côté elixip : `SIP.Context.set/3`,
> `appdata_set/3` et `assert_identity/2` photographient ce qu'elles produisent.
> Bancs : `apps/elixip2/test/fsl_state_exception_teardown_test.exs` (les trois
> cas du §5, contre-test compris) et `test/resilience_test.exs` du paquet.
> Le premier voisin du §8 — le dialogue qui ne surveillait pas son application —
> est corrigé dans la foulée (R7 de `DESIGN-SIPSTACK.md`, `bind_app/2` et la
> clause `{:DOWN, …}` de `SIP.DialogImpl`). Le second, la vérification de
> `ctx_set` à la compilation, reste ouvert.

> **Ce document est un prompt autoporteur.** Il donne à un agent (ou à un
> développeur) tout ce qu'il faut pour corriger le défaut décrit ici, sans avoir
> à refaire le diagnostic. Le défaut est **prouvé sur banc**, pas déduit : la
> reproduction est au §5, prête à coller.
>
> **À corriger de préférence sur `release/1.6.0`**, où FSL est sorti d'elixip
> (paquet hex `finite_state_language`, application OTP `:fsl`, dépôt
> `neutrino38/finite-state-language`). Le correctif tombe des deux côtés de la
> couture : voir §4.

## 1. Le défaut, en une phrase

Quand un état de scénario lève une exception, le teardown reçoit le contexte tel
qu'il était **à l'entrée de l'état**. Tout ce que cet état avait alloué est donc
invisible : les pattes B2BUA ne sont pas raccrochées, le média n'est pas libéré.
L'appel reste pendu des deux côtés.

La cause est une règle du langage Elixir : un `rescue` ne voit pas les liaisons
faites dans le `try`. Or la macro `state` entoure le corps entier de l'état d'un
`try/rescue/catch`, et le contexte est une **variable rebindée** (`var!(sip_ctx)`)
à chaque verbe.

```elixir
# 1.5.x — apps/elixip2/lib/dsl/SIPScenario.ex, defmacro state/2
try do
  unquote(body)          # media_connect(), call(), b2bua_forward()… rebindent sip_ctx
rescue
  e ->                   # ici, sip_ctx est celui d'AVANT le corps
    Logger.error("Exception in scenario state #{unquote(name)}")
    scenario_failure("exception!")
end
```

La clause `catch :exit, reason` juste en dessous a **exactement le même trou**.
Son commentaire annonce pourtant la propriété que ce prompt demande de rendre
vraie : « whatever happens the scenario ENDS, which is what runs the teardown
that answers the caller » (§14.4, R2). Elle fait finir le scénario ; elle ne
fait pas raccrocher l'appel.

## 2. Ce que ça a coûté en production

Le 2026-09-21 sur dev71, `recorded-call.exs` a levé dans son état `place_call` —
l'état qui fait `media_connect()` **et** monte les deux pattes. Suite :

- aucun BYE, ni vers l'appelant, ni vers l'appelé ;
- aucune libération média : le MCU a tenu jusqu'à son chien de garde RTP
  (« timeout on audio / video », 30 s plus tard) ;
- les requêtes intra-dialogue ont continué d'arriver sur un dialogue dont
  l'application était morte. Au bout de **4** transactions ouvertes
  (`SIP.DialogImpl.on_new_transaction/3`), le dialogue a répondu 503 — y compris
  au **BYE de l'appelant**, qui n'a donc pas pu raccrocher, puis 408 à
  l'expiration des transactions.

Le scénario fautif a été corrigé de son côté. Le défaut décrit ici, lui, est
générique : n'importe quelle exception dans n'importe quel état produit le même
appel fantôme.

## 3. Le verdict, et comment il a été établi

Deux exécutions du **même** scénario de banc, avec la **même** exception, à un
état de distance :

| Où l'exception est levée | BYE vers l'appelé | BYE vers l'appelant |
|---|---|---|
| dans l'état qui a monté l'appel (`place_call`) | **non** | **non** |
| un état plus tard (`bridging`) | oui | oui |

La différence est entière : dans le second cas, le contexte d'entrée de l'état
porte déjà les pattes, donc le teardown les voit. C'est la signature exacte du
retour en arrière du `rescue`, et rien d'autre ne l'explique.

## 4. Où vit le correctif

Le défaut est **à la couture** entre la macro `state` et le teardown. Les deux
moitiés ont bougé en 1.6.0 :

| | 1.5.x | 1.6.0 |
|---|---|---|
| la macro `state` (le `try/rescue`) | `apps/elixip2/lib/dsl/SIPScenario.ex` | paquet `:fsl` — `FSL.Machine` |
| le teardown | `SIP.Scenario.Runner.finalize/4` (`release_b2bua_legs` → `release_media`) | idem, en cours d'extraction vers `c:FSL.Host.finalize/1` (`SIP.FSL.Host`) — voir `elixir/docs/extraction-plan.md` §4.6 et `apps/elixip2/test/fsl_teardown_order_test.exs` |

Le contexte SIP reste un `%SIP.Context{}` porté par `FSL.Context` : le problème
n'est pas sa forme, c'est **qu'il vive dans une variable de pile**.

## 5. La reproduction

À poser dans `apps/elixip2/test/` (le harnais est celui de
`sbb_bridge_test.exs` : bouchon de dialogue entrant + transport mockup + pair
`Manual`). Il **échoue** aujourd'hui sur la première des deux assertions BYE.

```elixir
defmodule SIP.Test.FSL.StateExceptionTeardown do
  use ExUnit.Case, async: false

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  defmodule Exploding do
    use SIP.Scenario
    use SBB.Call

    uas(:invite)

    config(peer: "sip:callee@example.com:5060;unittest=state_exception")

    state initial_state do
      on_events do
        {:INVITE, req, _trans, _dlg} ->
          b2bua_reply(req, 100, "Trying")
          goto(place_call, "INVITE received")
      after
        5_000 -> scenario_failure("no INVITE")
      end
    end

    # L'état qui alloue ET qui lève. `:degraded` n'est pas une propriété du
    # contexte : SIP.Context.set/3 lève, exactement comme en production.
    state place_call do
      call(args: %{peer: ctx_get(:peer)})

      on_events do
        {:call, :connected, _} ->
          ctx_set(:degraded, [:inbound])
          goto(bridging, "call established")

        {:call, outcome, _} ->
          scenario_failure("not established: #{outcome}")
      end
    end

    state bridging do
      bridge()

      on_events do
        {:bridge, outcome, _} -> scenario_success("done: #{outcome}")
      end
    end
  end

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    :ok = SIP.Auth.Secret.start()
    :ok
  end

  setup do
    {:ok, stub} = SIP.Test.B2bua.InboundDialogStub.start_link(self())
    on_exit(fn -> if Process.alive?(stub), do: GenServer.stop(stub) end)
    %{stub: stub}
  end

  defp peer_uri do
    %SIP.Uri{scheme: "sip:", userpart: "callee", domain: "example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", "state_exception")
  end

  test "a state that raises still hangs both legs up", %{stub: stub} do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, invite} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    invite = Map.put(invite, :callid, SIP.Msg.Ops.generate_branch_value())

    tp = SIP.Transport.Selector.select_transport(peer_uri()).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)

    test_pid = self()

    {instance, ref} =
      spawn_monitor(fn ->
        outcome =
          SIP.Scenario.Runner.run_instance(Exploding,
            dialog_pid: stub,
            inbound_request: invite,
            config_overrides: [peer: peer_uri(), test_pid: test_pid]
          )

        send(test_pid, {:instance_done, outcome})
      end)

    send(instance, {:INVITE, invite, self(), stub})
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000
    Manual.simulate(tp, 200, 50)
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000

    send(instance, {:ACK, %{invite | method: :ACK, cseq: [1, :ACK]}, self(), stub})
    assert_receive {:sip_mockup, {:request_sent, :ACK, _}}, 5_000

    assert_receive {:instance_done, {:error, _}}, 10_000

    assert_receive {:sip_mockup, {:request_sent, :BYE, _}}, 5_000, "no BYE to the callee"
    assert_receive {:sent_on_inbound, %{method: :BYE}}, 5_000, "no BYE to the caller"

    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end
end
```

Le **contre-test** qui isole la cause : déplacer `ctx_set(:degraded, [:inbound])`
du bras `{:call, :connected, _}` vers le début de l'état `bridging`. Le banc
passe alors sans rien corriger. Garder les deux cas dans la suite finale : le
second interdit qu'on « répare » en ne testant que le cas facile.

## 6. Ce qu'il faut faire

Trois options ; la première est celle que je recommande.

### 6.1 Photographier le contexte hors de la pile — recommandé

Le contexte vivant est écrit dans le dictionnaire de processus à chaque
réécriture, et les clauses `rescue` et `catch` le relisent avant de basculer sur
l'échec.

- entonnoirs à instrumenter : `SIP.Context.set/3`, l'écriture d'`appdata`, et le
  `put_state/2` du B2BUA (c'est lui qui porte les pattes) ;
- la macro `state` commence ses clauses `rescue` et `catch` par une relecture :
  `var!(sip_ctx) = FSL.Context.latest(var!(sip_ctx))`, qui rend la photo quand
  elle est plus récente et l'argument sinon.

Coût : trois lignes dans les entonnoirs, deux dans la macro. Couvre l'exception
**et** l'exit d'un seul geste, sans toucher un seul verbe.

Piège à ne pas se créer : la photo est **par processus**, et une instance de
scénario est un processus. Un SBB tourne dans le processus de son hôte, donc
partage la photo — c'est ce qu'on veut. Un scénario enfant a la sienne.

### 6.2 Sortir le `try/rescue` de la macro vers le moteur

Le moteur (`FSL.Machine` / `Runner.run_state/3`) appelle la fonction d'état dans
son propre `try`, et les verbes qui allouent enregistrent leurs poignées côté
processus. Plus propre sur le papier — le contexte n'est plus le seul registre
des ressources —, bien plus large, et c'est une modification d'API de FSL.

### 6.3 Ne rien faire côté langage

C'est l'état actuel. Il fait reposer l'intégrité de l'appel sur la promesse
qu'aucun scénario ne lève jamais. Un `.exs` est écrit par un exploitant, chargé
sans compilation préalable : la promesse ne tient pas.

## 7. Recette

1. le banc du §5 passe, contre-test compris ;
2. `fsl_teardown_order_test.exs` reste vert : l'ordre
   enfants → pattes → média → `cleanup/1` → parent ne bouge pas ;
3. un `exit` provoqué dans un état (un `GenServer.call` vers un dialogue mort)
   raccroche les deux pattes de la même façon — c'est la clause `catch`, et elle
   a le même défaut ;
4. sur un nœud réel : un scénario qui lève après établissement produit un BYE
   des deux côtés dans la seconde, et le journal du MCU ne montre plus de
   session laissée à expirer.

## 8. Deux voisins, à traiter séparément

Ils sont apparus dans le même incident. Aucun n'est la cause, aucun ne disparaît
avec ce correctif.

- **Le dialogue ne surveille pas son application.** `SIP.DialogImpl` ne fait
  aucun `Process.monitor` sur `state.app`. Un dialogue survit donc à son
  scénario mort, occupe ses 4 places de transaction et répond 503, notamment au
  BYE de l'appelant. Un `:DOWN` devrait terminer le dialogue.
- **`ctx_set` ne vérifie rien à la compilation.** Une propriété inconnue écrite
  en atome littéral n'est refusée qu'à l'exécution, c'est-à-dire sur le premier
  appel d'un nœud en production. Le banc de chargement du script
  (`Code.compile_file/1`) ne peut pas la voir. La macro pourrait comparer un
  atome littéral aux champs du struct et refuser à la compilation.

## 9. Références

- journal de production : dev71, 2026-09-21 11:24:52 → 11:25:55 ;
- `apps/elixip2/lib/dsl/SIPScenario.ex`, `defmacro state/2` (1.5.x) ;
- `apps/elixip2/lib/dsl/SIPScenarioRunner.ex`, `finalize/4`,
  `release_b2bua_legs/1`, `release_media/1` ;
- `apps/elixip2/lib/framework/SIPSessionB2bua.ex`, `release_legs/1`,
  `wind_down_inbound/1` ;
- `apps/elixip2/lib/framework/SIPDialogImpl.ex`, `on_new_transaction/3` (la
  limite de 4) ;
- `docs/design/DESIGN-FSL.md` et, en 1.6.0, `elixir/docs/extraction-plan.md`
  §4.6 du dépôt `finite-state-language`.
