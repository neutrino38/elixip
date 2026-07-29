# Primitives B2BUA

L'ajout d'une fonction B2BUA est essentielle pour la suite du projet. Elle permettra de proposer des fonctions utiles pour les produits `borderline` et `kelixip`. Le principe de ces primitive est le suivant : 

- créer un second dialogue associé au scénario à l'aide d'une macro 
- le scénario dispose désormais de deux tronçons d'appels (legs). Le tronçons entrant (inbound) et le tronçon sortant (outbound). Les deux tronçons échangent les messages avec le scénario.
- le scénario sait différencier facilement les messages venant du tronçons sortant et du tronçons entrant.
- à la différence du t_relay() de kamailio ou du Dial() en AEL d'asterisk, le scénario doit gérer lui même le relais des requêtes SIP et de leur réponses entre les deux tronçons.

## Création du tronçon / dialogue outbound


## tronçon outbound et proxy

## Réceptions Requêtes et réponses SIP reçue par le tronçon outbound

Les deux dialogues envoient les evt. On doit disposer d'un discriminant qui permettent facilement de spécifier de gardes. Idéalement un truc comme 

``̀`Elixir
on event do
   { :MESSAGE, req, _trans_pid, dialog_pid} when is_outbound(dialog_pid) -> ...
end
```

Sinon, possibilité de 'tagger' le dialogue outbound pour qu'il envoie :

``̀`Elixir
on event do
   { :outbound, :MESSAGE, req, _trans_pid, dialog_pid}  -> ...
end
```

## Renvoi des requêtes et des réponses entre les tronçons

Après que la première macro forward_ ... est créé le dialogue outbound
