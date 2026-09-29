# Débogage avancé des scénarios

Ce document consigne le chantier « débogage des scénarios » d'`elixipp`. Il décrit
ce qui existe, comment c'est construit, ce qui manque, et ce qui vient ensuite.
La référence d'usage est dans [ELIXIPP.md](../../ELIXIPP.md), section
« Sequence diagram ». La conception côté SIP est dans
[DESIGN-FSL.md](DESIGN-FSL.md), section « `journal_started/1` and
`journal_collect/0` — the SIP trace » ; le journal et le rendu sont ceux du
package `finite_state_language` (`FSL.Journal`, `FSL.Diagram`). Le portage
après l'extraction de FSL est décrit dans
[debug-fsl-port-plan.md](debug-fsl-port-plan.md).

## Besoin

Quand un scénario échoue contre un vrai équipement, il faut voir ce qui s'est
passé sur le fil, message par message, avec les temps. Le fichier de log au
niveau `debug` contient les messages, mais sans lien avec l'instance de scénario,
sans ordre lisible, et noyés dans les traces des couches basses.

L'objectif : un diagramme de séquence d'une exécution **réelle**, produit par
l'outil lui-même, par instance de scénario.

## Ce qui existe pour déboguer

Trois sorties, du plus grossier au plus fin.

| Sortie | Ce qu'elle montre | Où |
|---|---|---|
| `--monitor` | Une ligne par instance en cours : commande, état, événement, médias, serveur, destination. Pas d'historique. | Console |
| `--log-level debug` | Tous les messages SIP en entier, plus les traces des couches transport, transaction et dialogue. | `elixipp.log` |
| `--log-sequence` ou `debug: true` | Un diagramme de séquence PlantUML par instance, tiré des messages réels. | `<scenario>_<pid>.puml` |

Il n'existe pas de capture pcap ni de `:telemetry` dans la pile SIP.

## Le diagramme de séquence

### Activation

Trois façons, équivalentes :

- l'option `--log-sequence` de la ligne de commande ;
- `debug: true` dans le bloc `config` du scénario ;
- `ctx_set(:debug, true)` dans un état. La boucle de `FSL.Runner` relit le
  drapeau après chaque état. Posé dans `initial_state`, le diagramme est
  complet. Posé plus tard, il commence à la transition qui suit — dessinée comme
  l'état atteint, sans son état d'origine — et le dialogue déjà ouvert est suivi
  à partir de là.

Le fichier est écrit dans le répertoire courant à la fin de l'instance.

### Contenu

Chaque ligne porte le temps écoulé depuis le début de l'instance (`+412ms`).

- **Les messages SIP réels**, tels que la couche transaction les a envoyés ou
  reçus. Requête en trait plein avec son numéro de CSeq (`INVITE #1`), réponse en
  pointillé avec la transaction qu'elle clôt (`200 OK / 1 INVITE`), retransmission
  en gris. `+SDP` quand le message porte une offre ou une réponse.
- **Un participant par Call-ID.** Un B2BUA montre ses deux pattes côte à côte. Une
  inscription suivie d'un appel donne deux voies. L'étiquette est le tag de patte
  quand le framework en a donné un au dialogue (`outbound`), puis l'adresse du
  pair et son transport (`10.0.0.1:5060/udp`), ou `peer N` quand aucun n'est
  connu. L'en-tête du fichier donne le Call-ID de chaque voie.
- **Les commandes du script** (`send_INVITE`, `send_BYE`) en notes hexagonales à
  côté des flèches qu'elles ont produites. On relie ainsi une ligne du script à
  ce qui est sorti.
- **Les commandes et événements média**, sur une voie `media server`.
- **Les transitions d'état** en notes, et l'issue finale en vert ou en rose.

Exemple d'un appel sortant :

```plantuml
participant "bob" as local
participant "10.0.0.1:5060/udp" as peer1

note over local : +0ms initial_state
hnote over local : +2ms send_INVITE
local -> peer1 : +3ms INVITE #1 +SDP
peer1 --> local : +9ms 100 Trying / 1 INVITE
peer1 --> local : +110ms 180 Ringing / 1 INVITE
peer1 --> local : +412ms 200 OK / 1 INVITE +SDP
local -> peer1 : +413ms ACK #1
note over local : +414ms calling -> answered
note over local #LightGreen : +415ms succeeded: answered
```

Sans aucun message tracé, par exemple un scénario qui n'a jamais atteint la
pile SIP, le rendu retombe sur ce que le script a rapporté : le nom des
commandes devient une flèche de requête, la description d'une transition SIP
devient une flèche entrante.

## Construction

### Ce que fait FSL, ce que fait SIP

Le journal et le rendu appartiennent au package `finite_state_language`, qui ne
connaît pas SIP. Il a appris une chose générique : des événements enregistrés
hors du processus de la machine, qu'une liaison lui remet. SIP s'y branche par
deux callbacks de `FSL.Host`.

| Module | Côté | Rôle |
|---|---|---|
| `FSL.Journal` | FSL | Journal chronologique de l'instance : commandes, transitions, issue. Chaque événement porte `:at` (µs monotones), les métadonnées `:t0`. Au `flush`, fusionne sur `:at` ce que l'hôte lui remet. |
| `FSL.Diagram.PlantUML`, `FSL.Diagram.Mermaid` | FSL | Rendu pur. Un événement `:message` passe le rendu en mode tracé : une voie par conversation, commandes en notes. |
| `SIP.Scenario.SipTrace` | SIP | Recueille les messages SIP émis et reçus pour le compte d'une instance, et construit les événements `:message`. Une table ETS publique, un GenServer propriétaire. |
| `SIP.FSL.Host` | SIP | `journal_started/1` : l'instance se déclare, adopte son dialogue, inscrit la requête qui l'a créée. `journal_collect/0` : `SipTrace.take/0`. |

L'événement `:message` porte `dir`, `lane` (le Call-ID), `party` (le tag de
patte), `peer` (l'adresse et le transport), `label` (`INVITE #1 +SDP`,
`200 OK / 1 INVITE`), `reply` (réponse : pointillé), `repeat` (retransmission :
grisé). SIP décide de ce que dit chaque champ ; le rendu dessine.

### Le point d'accroche : la couche transaction

Trois couches pouvaient porter la capture. Le choix s'est fait sur la
corrélation, pas sur la fidélité seule.

| Couche | Voit | Sait pour qui |
|---|---|---|
| Transport | Tout, octets compris | Rien : une socket |
| Transaction | Tout ce qui part et arrive, retransmissions et ACK/CANCEL fabriqués compris | Son `app` : le dialogue |
| Dialogue | Une copie de chaque message, sans retransmission, sans l'ACK d'un non-2xx | Le processus scénario |

La transaction voit tout et connaît son dialogue. Le dialogue connaît son
scénario. Deux sauts, une table.

Les points d'accroche, tous d'une ligne :

- émission : `SIP.Transac.Common.sendout_msg/2` (premier envoi), les deux
  timers de retransmission de `SIP.Trans.Timer`, le renvoi de la dernière
  réponse dans `SIP.IST` et `SIP.NIST` ;
- réception : les huit clauses `handle_cast({:onsipmsg, …})` de `SIP.ICT`,
  `SIP.NICT`, `SIP.IST` et `SIP.NIST`.

Un message retransmis depuis sa forme sérialisée est relu par `SIPMsg.parse/2`,
pas par une expression régulière : la lecture d'un message SIP reste dans la
couche message.

### La corrélation

La table ETS `:sip_scenario_trace` porte deux sortes de lignes :

- `{:watch, pid}` → `{scenario_pid, tag}` : qui trace pour qui. Le scénario s'y
  déclare lui-même au démarrage du journal (`journal_started/1`). Un dialogue
  s'y lie quand il apprend son pid applicatif, avec son tag de patte, dans
  `SIP.DialogImpl.bind_app/2`. Une instance UAS adopte le dialogue qui l'a fait
  naître, car ce dialogue existait avant elle.
- `{:event, scenario_pid, seq}` → événement : les messages, dans l'ordre.

`FSL.Journal` reprend les lignes au `flush` par `journal_collect/0`, les
fusionne avec ses propres événements sur `:at`, et rend le fichier. Il les
reprend aussi à `clear/0`, pour les jeter. Une instance UAS inscrit la requête
qui l'a créée avec `FSL.Journal.record/1` : elle a traversé la transaction avant
que quiconque ne trace.

### Coût quand personne ne trace

La table n'existe pas avant le premier scénario tracé. Chaque point d'accroche
commence par un `:ets.whereis` et s'arrête là. Quand la table existe, un message
d'un dialogue non tracé coûte une recherche par clé.

Le GenServer propriétaire surveille chaque scénario tracé et efface ses lignes
s'il meurt sans `flush`.

## Vérification

- Tests unitaires du puits : `apps/elixip2/test/sequence_trace_test.exs`.
  Enregistrement, forme `:message`, liaison d'un dialogue, adoption,
  retransmission relue depuis le fil, nettoyage à la mort du scénario.
- Tests du journal et du rendu, dans le package :
  `test/journal_trace_test.exs`. Horodatage, démarrage tardif, appel des deux
  callbacks, fusion sur `:at`, une voie par conversation, flèches, répétitions,
  notes, pour PlantUML et Mermaid ; un type d'événement inconnu est ignoré.
- Tests de bout en bout, dans `sequence_trace_test.exs` : un appel complet contre
  le transport factice (INVITE, 100, 180, 200, ACK, BYE, 200), chaque flèche
  vérifiée dans le fichier produit ; une instance UAS dont la première flèche est
  la requête qui l'a créée.

Essai en trafic réel le 2026-09-28 : `elixipp -c ives-wss.json
uac_invite_webrtc.exs --log-sequence`, appel WebRTC sur WSS vers dev71 avec média
Mendooze. Le diagramme contient tous les messages du log, dans l'ordre et aux bons
temps : INVITE, 407 et son ACK fabriqué par la transaction, INVITE authentifié,
deux 100, 180, 200 avec SDP, ACK, puis BYE et son 200. La voie porte le Call-ID
et l'adresse `dev71.dev.ives.fr:443/wss`. Pas encore essayé : un REGISTER réel, un
B2BUA, `kelictl debug` sur un nœud.

## Débogage à chaud dans kelixip

`kelictl debug <id> on` allume le journal d'une instance vivante ; `off` l'écrit
tout de suite. Le nœud garde le **journal**, pas un dessin : `Kelix.Traces`
conserve les événements et les métadonnées, et chaque lecteur dessine.
`kelictl debug show <id>` trace une échelle à la sngrep, `--full` y ajoute le
texte des messages, `--format-puml` donne le PlantUML ; kelescope dessine une
popup ([kelescope-debug-scenario.md](kelescope-debug-scenario.md)) ; REST
renvoie le journal en JSON. Guide opérateur :
[administration.md](../kelixip/administration.md#the-journal-of-a-live-scenario).

| Pièce | Côté | Rôle |
|---|---|---|
| Clause `{:scenario_ctl, :journal, :on \| :off}` | FSL 0.4.0 | Injectée dans chaque `on_events`, comme celle du shutdown. Allume le journal ou l'écrit, puis reprend l'attente avec le délai restant, sans rien signaler. Un seul journal par exécution : après `off`, aucun ne redémarre. |
| `joined_in` dans les métadonnées | FSL 0.4.0 | L'état dans lequel le journal a rejoint l'exécution : la première transition est dessinée depuis cet état. |
| `FSL.Host.journal_events/2` | FSL 0.4.1 | Le journal terminé, avant tout rendu. Un hôte qui le garde répond `{:ok, _}` et rien n'est dessiné ; sinon `:default` et FSL écrit le fichier. |
| `SIP.FSL.Host.journal_events/2` | SIP | Appelle le `{module, fonction}` de `:elixip2, :sequence_output` avec `(events, meta)`, sinon `:default`. Remet la colonne `traced` du moniteur à `false`. |
| `journal_started/1` | SIP | Surveille l'instance, adopte les dialogues déjà ouverts (pattes sortantes d'un B2BUA comprises, avec leur tag), met `traced` à `true`. |
| `SipTrace`, `SIPMsg.readable/1` | SIP | Chaque message porte son texte, corps décodé (`deflate`, `gzip`), coupé à 8 Kio. |
| `Kelix.Traces` | kelixip | Un journal par instance, en mémoire : `trace_retention` (3600 s), `max_traces` (100), `max_trace_bytes` (1 Mio, puis `:cut`). Pousse `{:kelix_traces, {:upsert \| :remove, _}}` aux abonnés. Perdu au redémarrage. |
| `Control.debug_scenario/2,3`, `traces/0`, `trace/1`, `subscribe_traces/1` | kelixip | La commande jusqu'à l'instance (un second `on` est refusé : `{:error, :journal_written}`), la relecture, les notifications. |
| `Kelix.Control.Ladder` | kelictl | L'échelle texte, dessinée à partir des événements gardés. |

Une instance occupée hors d'une attente voit la demande à sa prochaine attente ;
la colonne `traced` dit quand elle l'a prise.

## Limites connues

- Un message qui ne passe par aucune transaction liée à l'instance n'apparaît
  pas : une réponse sans état de la couche dialogue (un 481 à une requête sans
  dialogue), un OPTIONS reçu hors dialogue.
- `--log-sequence` est refusé avec `--limit > 1`. Un fichier par instance, une
  instance à la fois.
- Dans elixipp, le fichier est écrit dans le répertoire courant. Pas d'option
  pour choisir le dossier.
- L'adresse du pair d'une requête entrante initiale est inconnue : la première
  voie d'une instance UAS prend son étiquette sur le message suivant.

## Suite

Par ordre de priorité :

1. Compléter l'essai en trafic réel : un REGISTER, un B2BUA, et
   `kelictl debug <id> on` sur un nœud kelixip.
2. Lever la limite `--limit 1` : un fichier par instance nommé par Call-ID, ou
   un seul fichier pour la campagne.
3. Une option `--log-sequence-dir` pour le dossier de sortie.
4. Tracer les réponses sans état du dialogue et les OPTIONS hors dialogue, qui
   échappent aujourd'hui aux transactions liées.
