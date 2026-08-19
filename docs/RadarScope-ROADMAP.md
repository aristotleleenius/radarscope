# RadarScope — feuille de route

## Disponible dans la version 3.0

- `status` : état CPU, mémoire, disque, batterie, uptime et interface par défaut.
- `devices` : appareils visibles dans la table ARP locale.
- `connections` : connexions TCP/UDP et processus propriétaires via `lsof`.
- `snapshot` : export JSON regroupant système, réseau, état persistant et alertes récentes.
- `dashboard` : interface web locale, sans CDN ni dépendance Python supplémentaire.
- historique SQLite local avec graphiques CPU et débit réseau, sélectionnable par interface LAN/Wi-Fi ;
- topologie indicative dynamique construite à partir de la passerelle et de l’ARP, avec IP/MAC/hostname/interface/dernière vue et conservation des appareils récents ;
- vue graphique compacte séparée des machines découvertes, reliée à l’ordinateur et à la passerelle ;
- globe Internet après la passerelle avec l’IP publique observée et mise en cache temporairement ;
- inventaire USB/Bluetooth via `system_profiler` avec fallback I/O Registry ;
- résolution hostname multi-sources (`arp -a`, cache macOS, socket, mDNS et outils DNS disponibles) avec cache persistant ;
- profil matériel et logiciel local sans numéro de série ;
- scan des réseaux Wi-Fi voisins via `airport -s` avec repli `system_profiler` ;
- inquiry Bluetooth via `blueutil` avec repli sur les appareils appairés/connus ;
- actualisation manuelle des scans radio et séparation explicite du Wi-Fi courant, des autres réseaux et des appareils Bluetooth réellement détectés ;
- filtrage des entrées ARP incomplètes/multicast et des pseudo-hostnames DNS pour garder une carte lisible ;
- enrichissement optionnel des machines par découverte Nmap locale (`--active-discovery`) : fabricant, état et latence ;
- liste des interfaces LAN/Wi-Fi, y compris les ports déconnectés ;
- notifications macOS opt-in pour les nouveaux appareils ;
- filtres dashboard par application, port et adresse distante ;
- tests unitaires de parsing et exclusion des fichiers d’état sensibles par `.gitignore`.

## Prochaine étape recommandée

### 3.1 — historique et visualisation

- proposer l’export CSV pour les inventaires et diagnostics.

### 2.3 — détection et ergonomie

- ajouter une expiration des appareils et identités qui ne sont plus vus ;
- distinguer les alertes réseau, système et périphériques USB/Bluetooth ;
- ajouter des notifications macOS opt-in pour les changements critiques supplémentaires ;
- ajouter une liste blanche persistante par MAC, IP et processus ;
- ajouter un mode JSON événementiel pour brancher RadarScope à un autre outil local.

## Garde-fous

- le dashboard écoute sur `127.0.0.1` par défaut ;
- aucune capture de contenu applicatif n’est ajoutée ;
- les scans actifs restent réservés aux réseaux administrés ou explicitement autorisés ;
- les fichiers contenant IP, MAC et événements locaux restent exclus du dépôt.
