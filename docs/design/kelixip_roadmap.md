# kelixip roadmap — what is designed but not built

**Status: not implemented.** Extracted from the requirements and design documents
when they were consolidated into [`DESIGN-KELIXIP.md`](DESIGN-KELIXIP.md),
which keeps only what is built and running.

Related open designs, each with its own document:
[`evolution-auth-db.md`](evolution-auth-db.md) (replaceable backend) is to be implemented — the
authentication it would sit under is [`DESIGN-AUTH.md`](DESIGN-AUTH.md) — 
[`kelixip-b2bua.md`](kelixip-b2bua.md)
(`queue()` above the B2BUA primitives; `call()` shipped in 1.5.0),
[`integration-fail2ban.md`](integration-fail2ban.md),
[`kelixip_liveview.md`](kelixip_liveview.md) and
[`liveview-adapter.md`](liveview-adapter.md) (a web admin console),
[`mcu_server_evolutions.md`](mcu_server_evolutions.md) (media-server increments
[`moteli-reboot.md`](mcu_server_evolutions.md) (replacing XML-RPC communication by an RabbitMQ message bus)
for the conferencing module).

## Open items

| Item | Note |
|---|---|
| **`presence` function** | `SIP.Session.Presence` is a skeleton: the behaviour exists, no verbs, no script, no dispatch |
| **`Path` generation / multi-hop edge proxy** | `Path` is *honoured* today; emitting it as an edge proxy is not built |
| **usrloc persistence** | bindings live in memory; a restart loses them |
| **High availability (2-3 node cluster)** | §HA below |
| **`radius_billing` module** | designed as a `Kelix.Module` (P6b), never written |
| **`Kelix.InstanceSupervisor`** | instances are `spawn_monitor`ed by `Kelix.InstancePool`, which owns quota and drain. A `DynamicSupervisor` would add observability and lifecycle, and needs an opt-in option on `spawn_uas_instance/2`; functionally not required |

> Les renvois `§n` de cette section pointent vers le document de conception
> retiré ; l'équivalent implémenté est dans [`DESIGN-KELIXIP.md`](DESIGN-KELIXIP.md).

## registrar en mémoire & haute disponibilité — *futur*

C'est un module supplémentaire `registrar.beam`, `Kelix.Mod.Registrar`. 

Son rôle est de stocker les AOR (Address of Record) et les contacts des UA enregistrées. 
L'équilent kamailo est le module `registrar` + `usrloc`. Comme kamailio, il stocke: les AOR, 
c.-à-d. le **userpart du champ `To`** (l'AOR enregistré, conformément à la RFC 3261) et la
liste des contacts.

Pour chaque contact, il stocke également:

- le domaine
- la SIP URI du contact telle que présentée dans le message REGISTER
- Le transport, l'adresse IP et le port réel d'où vient le message REGISTER (note de conception : extraire cet info du dialogue ?)
- le PID du dialogue associé au register
- une info supplémentaire arbitraire fournie par le scénario

fournis par la fonction save() décrite plus bas.


Note de conception (à intégrer à DESIGN-KELIXIP.md le jour où c'est implémenté) : 

pouvoir séparer fortement les domaines. Je suggère : 

  **Décidé (2026-07-26) : une table ETS par domaine** (séparation forte), + un
  index `%{ "domain" => tid }`. La table d'un domaine est créée/supprimée avec le
  domaine ; purge par binding via un monitor du pid de dialogue. Détail dans
  `DESIGN-KELIXIP.md`.

  aor_map:

  %{ "aor" => [ contact_info1, ... ] }

  La gestion de l'expiration doit être traitée dans la couche dialogue. Tout cela doit s'appuyer sur la couche Dialogue et  SIP.Session.Registrar

On preprend la spec

Comme tout module, il est configuré par un bloc **`[module.registrar]`** — mais,
à la différence des autres modules (dont le bloc est dans `config.toml`), le
sien est placé dans **`domains.toml`** (fichier des domaines), car sa
configuration est liée aux domaines et **rechargeable à chaud**. Le
`Kelix.ModuleSupervisor` lit donc ce module depuis `domains.toml` et le
reconfigure lors d'un `reload_domains`.

Paramètre du bloc `[module.registrar]` :
- `max_contacts_per_aor` : le nombre max de contacts par AOR.

(Les bornes d'expiration `default_expires` / `min_expires` restent **par
domaine** dans `[domain.registrar]`, §3.2 — c'est de la config d'activation de la
fonction, distincte des paramètres du module.)

Il exporte quatre fonctions :

``̀ Elixir
save(req, domain, info \\ nil)
``̀ 
ou 
- req est un message REGISTER
- domaine
- info est une info arbitraire fournie par le scénario.

La fonction extrait le ou les contacts présent dans le message REGISTER, vérifie la validité
du expire et effectue l'enregistrement ou le désenregistrement. Elle **ne compose PAS** la
réponse SIP : elle renvoie `{ :ok, granted }` où `granted` porte les contacts et les
expires **réellement accordés** (après clamp). Le script s'en sert pour appeler
`SIP.Session.Registrar.accept_registration(req, dialog_pid, granted)`, qui échoe exactement
ce qui a été stocké (le 200 OK est ainsi cohérent avec le store *par construction*, sans
re-calcul des bornes). En cas d'erreur, elle renvoie `{ :error, { code, reason } }` et le
script appelle `reject_registration(...)`.

> Note de conception : les bornes d'expiration sont ainsi appliquées à **un seul endroit**
> (`save`), jamais dupliquées dans `accept_registration` — le helper ne fait qu'échoer
> `granted`. (Refactor du helper actuel qui re-fait `check_register`/`adjust`.)

Elle lit les paramètres dans la section `[domain.registrar]` (dans `domains.toml`, cf. §3.2)
pour valider les durées d'expiration. Elle s'abonne aux évènements du dialogue pour capter le
désenregistrement ou la coupure du transport. En particulier dans le cas des transport connecté
s'il y a rupture de connexion l'enregistrement est invalidé.

``̀ Elixir
lookup(reqn)
``̀ 

Cette fonction prend en entrée d'importe quel message SIP a relayer vers un UA enregistré. Elle
extrait le userpart de la R-URI de la requête et la prend comme AOR à joindre. Utilise le domain de la R-URI (le rabat sur le nom principal en cas d'utilisation d'un alias). Puis elle retourne
un liste de requêtes modifiées prêtes être envoyées vers l'UA enregistrée. Pour ce faire, pour chaque contact enregistré pour l'AOR, la fonction:

- crée une copîe de la requête initiale,
- remplace la R-URI de la requête initiale par exactement le contact
- enrichi les champs destip, destport et destproto de la R-URI

L'ensemble est retourné comme: 

``̀ Elixir
{ :ok, [ newreq1, newreq2 ... ] }
``̀ 

Aucun contact pour l'AOR :  retour `:notfound`

En cas d'erreur elle renvoie : `{ :error, reason }`

Note de conception, passer la R-URI des requêtes retournées par lookup() a TransportSelector.select_transport() doit permette de retrouver EXACTEMENT le transport utilisable pour joindre l'UA. C'est en particulier vrai pour les transports connectés comme TCP, TLS et WSS dont les client DOIVENT maintenir une connexion permanente avec le registrar.

**Décidé (2026-07-26) — `select_transport/1` doit honorer une R-URI déjà résolue**
(aujourd'hui il l'ignore et re-résout, cf. `DESIGN-KELIXIP.md`).
Court-circuit à deux niveaux : (1) si `tp_pid` est vivant → l'utiliser tel quel ;
(2) sinon si `destip` et `destport` sont présents → utiliser `destip`/`destport`/
`destproto` directement (`destproto = nil` ⇒ UDP par défaut), sans résolution DNS ;
(3) sinon résolution complète depuis la R-URI. `lookup()` renseigne `tp_pid` **et**
`destip`/`destport`/`destproto`.

La dernière fonction permet de souscrire/désouscrir aux évènements relatifs à un AOR@domain exprimé comme un `%SIP.Uri{}`

``̀ Elixir
subscribe_register_event(uri, pid)
unsubscribe_register_event(uri, pid)
``̀ 

Ce peut être pour un AOR non encore enregistré. Dans ce cas, le processus qui souscrit
reçoit :

``̀ Elixir
{ :registrar, :registered, aor@domaine }
{ :registrar, :unregistered, aor@domaine }
{ :registrar, :expired, aor@domaine }
{ :registrar, :disconnected, aor@domaine }
``̀ 



**Décision (basic) : l'usrloc reste 100 % en mémoire** (`Registry`), sans
persistance ni abstraction de stockage anticipée. Rationale :

- pour les transports **connectés** (WSS/TCP/TLS — l'essentiel de la cible
  WebRTC), persister l'usrloc à travers un redémarrage est de peu de valeur : la
  connexion est fermée au restart, le Contact pointerait vers un *flow* mort, le
  client doit se reconnecter et se ré-enregistrer de toute façon ;
- la persistance n'a de vraie valeur que pour l'**UDP** (sans connexion) et pour
  le **partage inter-nœuds** — qui relève de la HA, explicitement *futur*.


Note : le registrar (**location**) est distinct de l'auth (**subscriber**, gérée par
le module `auth_db`). Une future persistance usrloc serait une table
`location` séparée (comme chez Kamailio).

**Cluster 2-3 nœuds.** Cluster de **2 ou 3 instances** kelixip redondantes.

> Interviendra plus tard. Le registrar/usrloc et les dialogs étant **en mémoire**
> (choix ci-dessus), la clusterisation supposera alors de **factoriser l'usrloc
> derrière un store** (`SIP.Registrar.Store`, in-memory par défaut) et de fournir
> un backend répliqué (Mnesia / CRDT) ou *shared-nothing + persistance BDD*.
> Assumé comme un chantier au moment d'attaquer la HA, pas avant.

**Support natif des push notifications Google, iOS et Microsoft**

Une version ultérieur permettra d'associer à AOR avec un "contact" permettant de notifier
les applications mobiles iOS, Google et Microsoft par notification push. C'est un chantier
a faire pour une version utlérieure. Indépendante de la HA mais PAS en version basique.

