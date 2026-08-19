# RadarScope

`radarscope.py` est un outil de rappel et de surveillance réseau locale pour macOS. Il relaie au terminal les sorties de `nmap`, `arp` et `tcpdump` au fil de l’eau.

Depuis la version 3.0, RadarScope propose aussi une vue locale enrichie de l’ordinateur : métriques CPU/mémoire/disque/batterie, profil matériel et logiciel, machines connues par ARP avec résolution hostname multi-sources, connexions TCP/UDP associées aux processus, export JSON et dashboard web sans dépendance externe.

En mode `watch`, RadarScope conserve une baseline dans `radarscope_state.json` et journalise les alertes dans `radarscope_events.jsonl`. Le même fichier conserve le cache des associations hostname/IP/MAC.

La configuration par défaut est pensée pour rester lisible et légère : Nmap examine une petite liste de ports, `tcpdump` filtre le trafic TCP/ARP/ICMP, utilise un buffer de capture de 4096 KiB et ne conserve que les en-têtes de paquets. En mode `watch`, ARP est relevé toutes les 10 secondes et Nmap toutes les 30 secondes ; ces délais sont réglables.

Les couleurs sont en truecolor ANSI :

- vert : événement normal ;
- jaune : avertissement ;
- rouge : événement correspondant à une règle suspecte.

L’affichage compact aligne les niveaux et résume les lignes : `HOST`, `OPEN`, `ENTRY`, `TCP`, `ARP` et `ICMP`. Utilise `--display raw` si tu veux retrouver les lignes originales de `nmap`, `arp` et `tcpdump`.

Les règles rouges comprennent notamment :

- nouveau périphérique après la baseline ARP ;
- changement IP/MAC confirmé ou alternance entre plusieurs MAC ;
- nouveau port Nmap ouvert confirmé ;
- scan de nombreux ports ou hôtes dans une fenêtre courte ;
- scan FIN/NULL ;
- port sensible ciblé ou redirection ICMP.

Ce sont des heuristiques, pas une preuve d’attaque.

Les entrées ARP `incomplete` sont fréquentes pour des IP libres ou pendant un scan. Elles sont affichées en gris et regroupées dans un avertissement jaune, sans être classées comme une attaque.

## Installation

```sh
chmod +x radarscope.py
./radarscope.py doctor
```

Si `nmap` manque :

```sh
brew install nmap
```

## Utilisation

```sh
./radarscope.py man
./radarscope.py scan --target 127.0.0.1 --ports 22,80,443
./radarscope.py arp
./radarscope.py status
./radarscope.py devices
./radarscope.py connections
./radarscope.py snapshot > radarscope_snapshot.json
./radarscope.py dashboard
./radarscope.py dashboard --active-discovery
./radarscope.py capture --interface en0 --filter "tcp or arp" --sudo-tcpdump
./radarscope.py watch --target 192.168.1.0/24 --color always --sudo-tcpdump
./radarscope.py watch --target 192.168.1.0/24 --timing 4 --scan-interval 60 --sudo-tcpdump
./radarscope.py watch --target 192.168.1.0/24 --resolve-hostnames --arp-interval 10 --scan-interval 30 --timing 4 --sudo-tcpdump
./radarscope.py reset-hostnames
./radarscope.py watch --target 192.168.1.0/24 --display raw --sudo-tcpdump
```

`--timing 4` accélère Nmap sur un LAN fiable. Garde `T3` sur un réseau instable, distant ou très filtré. RadarScope utilise désormais `arp -a` pour récupérer les noms déjà connus par macOS, puis essaie le cache DNS système, `socket`, mDNS (`dns-sd`) et les outils `dig`/`host`/`nslookup` disponibles. Les noms trouvés sont mis en cache dans `radarscope_state.json` et associés à leur source. Le dashboard et `snapshot` activent la résolution par défaut ; passe `--no-resolve-hostnames` pour la désactiver. Lorsqu’une adresse IP est aussi associée à une MAC par ARP, le terminal affiche une ligne `IDENTITY host=hostname (IP) mac=...`, puis réutilise durablement ce libellé dans les lignes Nmap, ARP et TCP. `tcpdump` reste volontairement numérique pour conserver une détection temps réel fiable. `--active-discovery` complète l’ARP avec une découverte Nmap limitée au sous-réseau local pour obtenir fabricant, état et latence ; cette option n’est pas activée automatiquement. Pour modifier les délais, utilise `--arp-interval SEC` et `--scan-interval SEC`. Pour repartir de zéro sur les noms et les associations MAC, utilise `./radarscope.py reset-hostnames`. Pour observer absolument tout le trafic, passe un filtre vide avec `--filter ""`, en sachant que le terminal peut alors être très bavard.

## Vue locale et dashboard

Les commandes suivantes observent l’état déjà visible par macOS, sans lancer de scan actif :

- `./radarscope.py status` affiche la charge CPU, la mémoire, le disque `/`, la batterie, l’uptime et les compteurs locaux.
- `./radarscope.py devices` affiche la table ARP actuelle avec IP, MAC, interface et état.
- `./radarscope.py connections` affiche les connexions TCP/UDP et le processus qui les possède via `lsof`.
- `./radarscope.py snapshot` exporte un état JSON réunissant système, appareils, connexions et alertes récentes.
- `./radarscope.py dashboard` démarre une interface web sur `http://127.0.0.1:8765/`, actualisée toutes les trois secondes.

Le dashboard ajoute :

- un historique SQLite local avec graphiques CPU et débit réseau ;
- un sélecteur des interfaces LAN et Wi-Fi détectées par macOS, avec un historique de débit propre à l’interface sélectionnée ;
- un sélecteur qui conserve aussi les ports Ethernet, ponts et interfaces Wi-Fi déconnectés, avec leur état ;
- une carte topologique indicative basée sur la route par défaut et la table ARP, recalculée à chaque mesure et conservant les appareils vus récemment ;
- une vue graphique compacte séparée qui relie l’ordinateur, la passerelle et les machines découvertes, avec IP, état, MAC et interface quand disponibles ;
- la passerelle est prolongée par un globe Internet et l’IP publique observée depuis cette connexion, mise en cache quelques minutes ;
- les noms d’hôtes connus, IP, MAC, interface et dernière observation dans la carte et la table des appareils ;
- l’inventaire USB et Bluetooth fourni par macOS, avec repli sur l’I/O Registry quand `system_profiler` ne retourne pas les appareils ;
- le profil matériel et logiciel de l’ordinateur local, sans numéro de série ;
- les réseaux Wi-Fi visibles autour de l’ordinateur via le scanner natif macOS ;
- les appareils Bluetooth proches via `blueutil` si installé, avec repli sur les appareils appairés/connus de macOS ;
- une rubrique radio séparant le réseau Wi-Fi courant des autres réseaux, avec un bouton d’actualisation Wi-Fi/Bluetooth ;
- les machines enrichies par hostname, source de résolution, fabricant et latence lorsque `--active-discovery` est activé ;
- le filtrage des entrées ARP incomplètes, multicast et des réponses DNS techniques (`NXDOMAIN`, `found`, etc.) afin d’éviter la pollution de la carte ;
- des filtres par application, port et adresse distante ;
- des notifications macOS opt-in pour les appareils nouveaux.

Pour activer explicitement la résolution DNS inverse des appareils visibles (elle est déjà active par défaut dans le dashboard) :

```sh
./radarscope.py dashboard --resolve-hostnames
```

L’accès aux réseaux Wi-Fi peut nécessiter l’autorisation de localisation macOS. Sur les versions récentes de macOS, l’ancien utilitaire `airport` peut être absent et `system_profiler` peut renvoyer les SSID sous la forme `<redacted>` ou ne pas fournir le BSSID/RSSI ; RadarScope conserve alors les canaux, bandes et informations de sécurité disponibles et indique la source utilisée. La découverte Bluetooth des appareils réellement proches peut nécessiter l’autorisation Bluetooth et `blueutil` (`brew install blueutil`). Sans ces autorisations ou outils facultatifs, RadarScope affiche explicitement la source de repli et ne fabrique pas de données ; dans ce cas, les appareils appairés sont signalés comme tels et non comme « proches » confirmés.

La courbe réseau est calculée à partir des compteurs cumulés fournis par macOS (`netstat`). Si ces compteurs sont bloqués ou absents, le dashboard l’indique explicitement et n’affiche pas de faux débit. L’IP publique est obtenue par une requête courte vers un service externe (`api.ipify.org`) et n’est jamais écrite dans l’historique SQLite. Les liens de la carte représentent une relation déduite de l’ARP et de la passerelle, pas le câblage réel d’un switch ou d’un point d’accès.

Le dashboard reste attaché à `127.0.0.1` par défaut et ne charge aucune ressource externe. Pour changer le port :

```sh
./radarscope.py dashboard --port 9000
# historique conservé 48 h, mesure toutes les 5 secondes, notifications activées
./radarscope.py dashboard --history-hours 48 --history-interval 5 --notify-new-devices
```

Il faut lancer cette commande dans un terminal et laisser ce terminal ouvert pendant l’utilisation. Ensuite, ouvre `http://127.0.0.1:8765/` dans le navigateur. Si le navigateur indique que le site est inaccessible, le serveur RadarScope n’est généralement pas lancé ; relance la commande ci-dessus et vérifie que le message `dashboard actif` apparaît.

La base `radarscope_history.sqlite3` contient uniquement des compteurs et observations locales. Elle est ignorée par Git avec ses fichiers SQLite temporaires. La carte réseau est une déduction visuelle : elle ne prétend pas connaître les liens physiques d’un switch ou d’un point d’accès.

`--host 0.0.0.0` rend l’interface accessible depuis le réseau ; ne l’utilise que si tu comprends le risque et que le réseau est de confiance. Le dashboard affiche des métadonnées de connexions et des en-têtes réseau, pas le contenu des communications.

## Règles et historique

Le premier lancement crée la baseline sans déclarer tous les appareils existants comme suspects. Les changements d’ARP et de ports sont demandés deux fois par défaut avant de devenir rouges. Une même alerte est ensuite limitée par un délai de 120 secondes.

Exemple avec liste blanche et seuils adaptés à un petit réseau :

```sh
./radarscope.py watch \
  --target 192.168.1.0/24 \
  --allow-host 192.168.1.1 \
  --scan-window 15 \
  --scan-ports-threshold 15 \
  --scan-hosts-threshold 8 \
  --state-file radarscope_state.json \
  --event-log radarscope_events.jsonl \
  --sudo-tcpdump
```

`--allow-host` peut être répété ou recevoir plusieurs IP séparées par des virgules. L’adresse IPv4 de l’interface locale est ignorée automatiquement afin que le propre scan Nmap de RadarScope ne soit pas considéré comme une attaque.

Pour désactiver la persistance :

```sh
./radarscope.py watch --state-file none --event-log none --target 192.168.1.0/24
```

Pour tester les commandes sans lancer de scan ni de capture :

```sh
./radarscope.py watch --interface en0 --target 192.168.1.0/24 --dry-run
```

Utilise `--help` sur une commande pour voir ses paramètres. `Ctrl-C` arrête proprement la surveillance.

## Autorisation

Lance les scans uniquement sur des machines et réseaux que tu administres ou pour lesquels tu as une autorisation explicite. `tcpdump` peut demander les droits administrateur sur macOS ; l’option `--sudo-tcpdump` ne concerne que cette commande.
