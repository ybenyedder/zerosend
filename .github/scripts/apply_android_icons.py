#!/usr/bin/env python3
"""Installe l'icône ZeroSend dans le projet Android que Tauri régénère à chaque
`tauri android init` (src-tauri/gen/android est gitignoré — impossible d'éditer
à la main une fois pour toutes, comme pour le patch de signature).

Sans ce script, le launcher Android reçoit un simple PNG carré et le pose,
réduit, sur un cercle blanc généré → « petit carré dans un grand cercle blanc ».
On le remplace par une vraie icône adaptative (anydpi-v26) : fond bleu vectoriel
plein cadre + flèche blanche dans la zone de sécurité, plus des mipmaps raster
de repli pour Android < 8.

À lancer après `tauri android init` et avant `tauri android build`.
Échoue (code non nul) si l'arborescence res attendue est absente, plutôt que de
livrer silencieusement l'icône par défaut.
"""
import pathlib
import shutil
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
SRC = REPO / "src-tauri" / "icons" / "android-res"
RES = REPO / "src-tauri" / "gen" / "android" / "app" / "src" / "main" / "res"


def main() -> int:
    if not SRC.is_dir():
        print(f"source d'icônes introuvable : {SRC}", file=sys.stderr)
        return 1
    if not RES.is_dir():
        print(
            f"répertoire res Android introuvable : {RES}\n"
            "Lancer `tauri android init` avant ce script.",
            file=sys.stderr,
        )
        return 1

    copied = 0
    for src_file in sorted(SRC.rglob("*")):
        if src_file.is_dir():
            continue
        rel = src_file.relative_to(SRC)
        dst = RES / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_file, dst)
        copied += 1
        print(f"  + {rel}")

    # Le gabarit Tauri livre un avant-plan "robot Android" par défaut dans
    # drawable-v24/ qui, étant plus spécifique, masquerait notre flèche pour
    # @drawable/ic_launcher_foreground sur API 24+. On l'écrase par notre flèche.
    default_v24 = RES / "drawable-v24" / "ic_launcher_foreground.xml"
    if default_v24.exists():
        shutil.copy2(SRC / "drawable" / "ic_launcher_foreground.xml", default_v24)
        print("  ~ drawable-v24/ic_launcher_foreground.xml (remplacé par la flèche)")

    if copied == 0:
        print("aucun fichier d'icône copié — overlay vide ?", file=sys.stderr)
        return 1

    print(f"icône ZeroSend installée ({copied} fichiers).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
