# ZeroSend

Un partage de fichiers local, moderne et rapide — pensé comme une alternative
à LocalSend, bâtie sur Tauri 2 (Rust + webview native) pour rester légère sur
PC (Linux / macOS / Windows) et sur mobile (Android / iOS).

## Installation

Binaires précompilés disponibles sur la page
[Releases](https://github.com/ybenyedder/zerosend/releases) : `.AppImage` et
`.deb` (Linux), `.exe` (Windows, installeur NSIS), `.dmg` (macOS), `.apk`
(Android). Voir « Limites connues » plus bas : ces binaires ne sont pas
signés par un éditeur reconnu (pas de certificat Windows/Apple), donc le
système d'exploitation affichera un avertissement au premier lancement ;
l'APK Android est signé par une clé dédiée au projet (pas celle d'un compte
Play Store) et n'est distribué que via GitHub Releases, pas un store.

## Le principe : zéro requête externe

ZeroSend ne contacte **jamais** internet. Aucune télémétrie, aucun
crash-reporter, aucun vérificateur de mise à jour, aucune police ou ressource
chargée depuis un CDN, aucune résolution DNS vers un service tiers. Les deux
seules choses que l'application fait sur le réseau :

1. **Annoncer/découvrir** les autres appareils par broadcast UDP sur le
   réseau local (port `58017`, adresse `255.255.255.255` — non routable au-
   delà du sous-réseau local).
2. **Transférer des fichiers** en HTTPS directement entre deux appareils
   découverts de cette manière, sur un port TCP éphémère choisi par l'OS.

Ces garanties sont appliquées à plusieurs niveaux, pas seulement par
politique :

- La webview frontend a une CSP (`tauri.conf.json`) qui interdit tout
  `fetch`/`XHR` vers autre chose que `'self'` et le canal IPC interne de
  Tauri. La page ne peut techniquement pas faire de requête réseau elle-même.
- Tout le réseau (UDP + HTTPS) est géré côté Rust. Le seul hôte que le client
  HTTPS (`src-tauri/src/client.rs`) contacte jamais est l'adresse IP d'un
  pair obtenue via le broadcast UDP local — jamais un nom de domaine, jamais
  une IP saisie par l'utilisateur depuis l'extérieur.
- Aucune dépendance d'updater, d'analytics ou de crash-reporting n'est
  présente dans `Cargo.toml` / `package.json`.
- `createUpdaterArtifacts` est désactivé et aucun plugin updater Tauri n'est
  installé.

## Modèle de confiance

Comme les certificats sont auto-signés (pas d'autorité de certification sur
un réseau local), la confiance ne repose pas sur la chaîne TLS classique mais
sur quatre mécanismes complémentaires :

- **mTLS (certificat client obligatoire)** : toute connexion entrante doit
  présenter un certificat TLS client et prouver, via la signature du
  handshake, qu'elle possède la clé privée correspondante. L'empreinte ainsi
  *prouvée* doit correspondre à celle que l'expéditeur déclare — le nom et
  l'empreinte affichés sur la carte d'acceptation ne sont donc pas de
  simples déclarations.
- **Mémorisation au premier contact (TOFU, comme `known_hosts` en SSH)** :
  la première empreinte vue pour un appareil est mémorisée ; toute annonce
  ou demande ultérieure du même appareil avec une empreinte différente est
  rejetée. Le panneau des paramètres liste les appareils mémorisés et permet
  d'en « oublier » un dont l'identité a légitimement changé (réinstallation).
- **Chaque réception doit être acceptée explicitement** par l'utilisateur,
  avec le nom de l'expéditeur et son empreinte affichés avant d'accepter.
  Si la confirmation est désactivée dans les paramètres, seuls les appareils
  *déjà mémorisés* sont acceptés automatiquement — un appareil jamais vu
  repasse toujours par la carte d'acceptation.
- **L'empreinte SHA-256** du certificat de chaque appareil est affichée dans
  ses paramètres : deux utilisateurs peuvent la comparer de vive voix pour
  confirmer qu'ils parlent bien au bon appareil (même principe que les
  « numéros de sécurité » de Signal) — c'est ce qui couvre la limite
  intrinsèque du TOFU au tout premier contact.

Le transport reste chiffré par TLS 1.3 dans tous les cas et protège contre
l'écoute passive ; le serveur plafonne par ailleurs les demandes en attente,
le nombre de fichiers par demande et la taille reçue (jamais plus que ce qui
a été annoncé et accepté).

Deux options complètent ce modèle dans les paramètres :

- **Mode invisible** : l'appareil cesse d'annoncer sa présence sur le réseau
  (il disparaît de la liste des autres appareils en quelques secondes) tout
  en restant capable de voir les autres et de leur envoyer des fichiers.
- **Taille maximale par transfert** : un plafond en Mo (0 = illimité) sur le
  total annoncé d'une demande — toute demande qui le dépasse est refusée
  avant même la carte de confirmation, y compris venant d'un appareil de
  confiance en acceptation automatique.

## Architecture

```
src-tauri/src/
  identity.rs   identité persistante de l'appareil (id, nom)
  tls.rs        certificat TLS auto-signé, persisté, empreinte SHA-256
  discovery.rs  annonce + écoute UDP broadcast sur le LAN (port 58017)
  server.rs     serveur HTTPS (axum + rustls) qui reçoit les transferts
  client.rs     client HTTPS (reqwest) qui envoie les fichiers à un pair
  state.rs      état partagé (pairs connus, paramètres, transferts en cours)
  commands.rs   commandes exposées au frontend (invoke)
  types.rs      structures partagées (JSON sur le fil et événements UI)

src/
  main.ts       logique d'interface (aucun framework, TypeScript pur)
  styles.css    design (glassmorphism, dégradé, thème sombre)
  index.html    structure de la page
```

Protocole v2 (sur le LAN uniquement ; toute l'API HTTPS exige un certificat
client TLS — voir « Modèle de confiance ») :

- `UDP 58017` — paquets `Announce` JSON diffusés toutes les ~2 s (id, nom,
  plateforme et empreinte de l'appareil).
- `POST /api/transfer/request` — propose un transfert, attend l'acceptation
  (jusqu'à 120 s) ou répond immédiatement si l'expéditeur est déjà mémorisé
  et que la confiance automatique est activée.
- `PUT /api/transfer/{transfer_id}/files/{file_id}` — envoie le contenu d'un
  fichier, en streaming, depuis la même identité TLS que la demande.

## Développement

Prérequis : Node.js, Rust (`rustup`), et sur Linux les paquets système Tauri :

```sh
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev \
  libjavascriptcoregtk-4.1-dev librsvg2-dev libayatana-appindicator3-dev \
  build-essential libssl-dev
```

```sh
npm install
npm run tauri dev      # lance l'app en mode développement
npm run tauri build    # build de production (binaire + installeurs)
```

## Compiler pour les autres plateformes

Ce dépôt a été développé et testé sur Linux (x86_64). Tauri 2 partage un seul
code source pour toutes les cibles, mais chaque plateforme doit être compilée
depuis un système correspondant (ou via CI) :

- **Windows** : `npm run tauri build` sur une machine Windows avec les
  [outils de build Visual Studio](https://tauri.app/start/prerequisites/#windows)
  installés.
- **macOS** : `npm run tauri build` sur un Mac avec Xcode Command Line Tools.
- **Android** : `npm run tauri android init` puis
  `npm run tauri android build` (nécessite Android Studio / le SDK Android).
- **iOS** : `npm run tauri ios init` puis `npm run tauri ios build`
  (nécessite Xcode, donc un Mac).

`.github/workflows/release.yml` fait exactement ça à chaque tag `v*` poussé :
une matrice `[ubuntu-22.04, windows-latest, macos-latest]` (deb/AppImage,
exe, dmg) plus un job `publish-android` dédié qui régénère le projet Android,
le signe avec la clé de release du projet (stockée chiffrée dans les secrets
du dépôt, jamais commitée) et attache l'APK à la même release GitHub. iOS
n'est pas automatisé (nécessite un compte Apple Developer payant pour
signer, hors de portée d'un simple workflow CI gratuit).

## Limites connues (v0.2)

- Un appareil en v0.1 ne peut plus *envoyer* vers un appareil en v0.2 (le
  serveur exige désormais un certificat client) — l'inverse fonctionne.
  Mettez à jour les deux appareils.
- Pas de reprise sur erreur réseau en cours de transfert (à relancer
  manuellement).
- Pas d'envoi de dossiers entiers (uniquement des fichiers individuels,
  plusieurs à la fois).
- La découverte repose sur le broadcast IPv4 ; certains réseaux Wi-Fi avec
  « isolation client » actif peuvent bloquer le broadcast entre appareils
  (limite matérielle/réseau, pas applicative).
- Binaires Windows/macOS non signés par un certificat éditeur reconnu (pas
  de notarisation Apple, pas de certificat de signature de code Windows) —
  attendez-vous à un avertissement SmartScreen/Gatekeeper au premier
  lancement. L'APK Android est signé (nécessaire pour être installable) mais
  par une clé auto-générée propre à ce dépôt, pas par un compte Google Play.
- Pas de build iOS (nécessite un Mac + compte Apple Developer, non
  automatisé dans la CI actuelle).
