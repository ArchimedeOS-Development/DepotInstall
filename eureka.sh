#/bin/sh
# strap-archimedeos.sh - Installe le dépôt ArchimèdeOS sur Arch Linux

ARCH=$(uname -m)

MIRROR_F='archimedeos-mirrorlist'
MIRROR_URL='https://github.com/ArchimedeOS-Development/mirrorlist/blob/main/archimedeos-mirrorlist'
KEYRING_URL='https://github.com/ArchimedeOS-Development/ArchimedeOS-Development.github.io/raw/main/x86_64/archimedeos-keyring-20250612-3-any.pkg.tar.zst'
KEYRING_SIG_URL='https://github.com/ArchimedeOS-Development/ArchimedeOS-Development.github.io/raw/main/x86_64/archimedeos-keyring-20250612-3-any.pkg.tar.zst.sig'
GPG_KEY_ID='6C250CE3FE1635D3A3346BDD7F068AC1F1E5B246'

GPG_CONF='/etc/pacman.d/gnupg/gpg.conf'

err() { echo >&2 "$(tput bold; tput setaf 1)[-] ERREUR: ${*}$(tput sgr0)"; exit 1337; }
warn() { echo >&2 "$(tput bold; tput setaf 3)[!] AVERTISSEMENT: ${*}$(tput sgr0)"; }
msg() { echo "$(tput bold; tput setaf 2)[+] ${*}$(tput sgr0)"; }

check_priv() { [ "$(id -u)" -eq 0 ] || err "Vous devez être root."; }

make_tmp_dir() {
  tmp="$(mktemp -d /tmp/archimedeos_strap.XXXXXXXX)"
  trap 'rm -rf $tmp' EXIT
  cd "$tmp" || err "Impossible d'entrer dans $tmp"
}

set_umask() { OLD_UMASK=$(umask); umask 0022; trap 'umask $OLD_UMASK' TERM; }

check_internet() {
  curl -s --connect-timeout 8 https://archlinux.org/ > /dev/null 2>&1 || err "Pas de connexion Internet !"
}

add_gpg_opts() {
  grep -q 'allow-weak-key-signatures' $GPG_CONF || echo 'allow-weak-key-signatures' >> $GPG_CONF
}

fetch_keyring() {
  curl -LO "$KEYRING_URL" || err "Impossible de télécharger le keyring"
  curl -LO "$KEYRING_SIG_URL" || warn "Impossible de télécharger la signature du keyring"
}

verify_keyring() {
  gpg --keyserver keyserver.ubuntu.com --recv-keys "$GPG_KEY_ID" > /dev/null 2>&1 || \
  gpg --keyserver hkps://keyserver.ubuntu.com:443 --recv-keys "$GPG_KEY_ID" > /dev/null 2>&1 || \
  gpg --keyserver hkp://pgp.mit.edu:80 --recv-keys "$GPG_KEY_ID" > /dev/null 2>&1 || \
  err "Impossible de récupérer la clé GPG."
  gpg --keyserver-options no-auto-key-retrieve --with-fingerprint "$(basename "$KEYRING_SIG_URL")" > /dev/null 2>&1 || \
  err "Signature du keyring invalide."
}

delete_signature() { [ -f "$(basename "$KEYRING_SIG_URL")" ] && rm "$(basename "$KEYRING_SIG_URL")"; }

check_pacman_gnupg() { pacman-key --init; }

install_keyring() {
  pacman --config /dev/null --noconfirm -U "$(basename "$KEYRING_URL")" || err "Échec de l'installation du keyring"
  pacman-key --populate
}

get_mirror() {
  mirror_p="/etc/pacman.d"
  msg "Téléchargement de la liste des miroirs..."
  curl -s "$MIRROR_URL" -o "$mirror_p/$MIRROR_F" || err "Impossible de télécharger la mirrorlist"
  msg "Vous pouvez modifier le miroir par défaut dans $mirror_p/$MIRROR_F"
}

update_pacman_conf() {
  sed -i '/archimedeos/{N;d}' /etc/pacman.conf
  cat >> "/etc/pacman.conf" << EOF
[archimedeos]
Include = /etc/pacman.d/$MIRROR_F
EOF
}

pacman_update() {
  pacman -Syy || warn "Synchronisation pacman échouée. Essayez : pacman -Syy"
}

pacman_upgrade() {
  echo 'Faire une mise à jour complète du système ? (pacman -Su) [Yn]:'
  read conf < /dev/tty
  case "$conf" in
    ''|y|Y) pacman -Su ;;
    n|N) warn 'Certains paquets ArchimèdeOS peuvent ne pas fonctionner sans un système à jour.' ;;
  esac
}

archimedeos_setup() {
  msg 'Installation du keyring ArchimèdeOS...'
  check_priv
  set_umask
  make_tmp_dir
  check_internet
  add_gpg_opts
  fetch_keyring
  #verify_keyring # Décommente si tu veux vérifier la signature
  delete_signature
  check_pacman_gnupg
  install_keyring

  echo
  msg 'Keyring installé avec succès'
  if ! grep -q "\[archimedeos\]" /etc/pacman.conf; then
    msg 'Configuration de pacman'
    get_mirror
    msg 'Mise à jour de pacman.conf'
    update_pacman_conf
  fi
  msg 'Mise à jour des bases de paquets'
  pacman_update
  msg 'ArchimèdeOS est prêt !'
}

archimedeos_setup
