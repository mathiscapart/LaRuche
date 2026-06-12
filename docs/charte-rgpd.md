# Charte de collecte de données — Projet « La Ruche » (M1SPRO)

> Honeypot multi-services à finalité pédagogique et de recherche en sécurité.
> Charte établie en application du **RGPD**, de l'**article 323-1 du Code pénal**
> et des recommandations **ENISA — *Proactive Detection of Security Incidents:
> Honeypots***. Document de cadrage (B0), signé par les 4 membres de l'équipe.

---

## 1. Finalité et nature du dispositif

« La Ruche » est un **honeypot** : un système leurre **passif**, exposé
volontairement, dont l'unique objet est d'**observer et journaliser** les
tentatives d'attaque qui lui sont spontanément adressées, à des fins de :

- recherche et apprentissage en cybersécurité (analyse comportementale, TTP) ;
- production d'indicateurs de compromission (IOC) et de statistiques agrégées.

Le dispositif **ne fournit aucun service réel** et **n'héberge aucune donnée de
production**. Toute interaction avec lui émane d'un tiers qui **sollicite de
lui-même** le système ; aucune donnée n'est collectée auprès d'utilisateurs
légitimes.

## 2. Cadre légal — passivité et non-provocation (article 323-1)

- Le honeypot est **strictement défensif et passif** : il **n'attaque pas**, ne
  scanne pas, ne réplique pas vers des tiers, et n'exécute **aucune réponse
  active** (pas de *hack-back*). Décision tracée dans le backlog (US-32).
- Il **ne provoque ni n'incite** à l'infraction : il se contente d'exister et
  d'enregistrer. Il ne constitue donc pas un acte d'**entrapment**.
- Les comptes acceptés sont des comptes **faibles et fictifs** ; le compte
  `root` est toujours refusé. Aucune donnée réelle n'est exposée comme appât
  au-delà de leurres manifestement fabriqués.
- L'exposition Internet (US-36) est **limitée dans le temps** (fenêtre de
  quelques heures) sur un **VPS jetable** dédié, sans lien avec un SI réel.

## 3. Données collectées

Sont journalisés, par événement, au format `event.schema.json` :

| Donnée | Exemple | Caractère personnel |
|---|---|---|
| Adresse IP source | `203.0.113.7` | **Oui** (donnée à caractère personnel au sens RGPD) |
| Port source, horodatage, identifiant de session | — | Non, mais rattachables |
| Identifiants tentés (login / mot de passe) | `admin / admin123` | Possible (saisis par l'attaquant) |
| Commandes, requêtes HTTP, chemins, *user-agents* | `wget http://…` | Possible |
| Enrichissement : pays, ASN, score de réputation | GeoIP / AbuseIPDB / GreyNoise | Dérivé de l'IP |

**Aucune donnée sensible** au sens de l'article 9 du RGPD n'est recherchée ni
collectée intentionnellement.

## 4. Base légale et minimisation

- **Base légale** : intérêt légitime (art. 6.1.f RGPD) — sécurité des systèmes
  d'information et recherche défensive — dans un cadre **pédagogique encadré**.
- **Minimisation** : seules les données techniques nécessaires à l'analyse des
  attaques sont conservées. Aucun profilage d'individu identifié n'est réalisé ;
  les « profils » produits (bot / bruteforcer / human / scanner) qualifient un
  **comportement de session**, pas une personne.

## 5. Conservation, anonymisation et diffusion

- **Durée de conservation** : les journaux bruts sont conservés le temps du
  projet (semaine 13) puis **supprimés ou anonymisés** à sa clôture.
- **Anonymisation avant diffusion** : tout *dump* remis (rapport, livrables,
  partage MISP) est **anonymisé** — les adresses IP sources sont **masquées /
  tronquées** (ex. `203.0.113.x`) ou remplacées par un pseudonyme stable. Seules
  des **statistiques agrégées** (top pays, top credentials, volumétrie) sont
  présentées au jury.
- **Pas de recoupement** visant à ré-identifier une personne physique.

## 6. Sécurité du dispositif lui-même

- Conteneurs **non-root**, système de fichiers en **lecture seule**,
  `no-new-privileges`, limites de ressources, **segmentation réseau** isolant
  les données collectées d'un conteneur honeypot compromis (US-21).
- Le pipeline de collecte (OpenObserve) n'est **pas exposé** sur Internet :
  accès restreint à la *loopback* via tunnel SSH.
- Intégrité : les journaux sont centralisés en flux append-only (Fluent Bit) ;
  toute exploitation se fait sur copie.

## 7. Droits des personnes

Le dispositif ne permet pas, par construction, de contacter les personnes
concernées (attaquants anonymes et non sollicités). En cas de demande légitime
et identifiable, l'équipe s'engage à examiner toute requête d'accès ou
d'effacement dans la limite des données détenues et de la durée de conservation
ci-dessus.

## 8. Engagement de l'équipe

Les signataires s'engagent à n'utiliser le honeypot et les données collectées
qu'aux **seules fins pédagogiques et de recherche** décrites ci-dessus, à
respecter la passivité du dispositif, et à anonymiser toute donnée diffusée.

| Membre | Rôle (binôme) | Date | Signature |
|---|---|---|---|
| _Nom Prénom_ | A — Sécu offensive & Validation | __/06/2026 | ____________ |
| _Nom Prénom_ | A — Sécu offensive & Validation | __/06/2026 | ____________ |
| _Nom Prénom_ | B — Construction & Blue Team | __/06/2026 | ____________ |
| _Nom Prénom_ | B — Construction & Blue Team | __/06/2026 | ____________ |

---

*Références : RGPD (UE 2016/679) ; article 323-1 du Code pénal ; ENISA,
*Proactive Detection of Security Incidents — Honeypots* ; MITRE Engage
(Adversary Engagement Framework).*
