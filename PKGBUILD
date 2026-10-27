# Maintainer: Ozan Özdil
pkgname=omarchy-security-sentinel
pkgver=1.5.0
pkgrel=1
pkgdesc="Unified Cyber Security & Privacy Sentinel Hub for Omarchy Linux"
arch=('x86_64')
url="https://github.com/ozdil/omarchy-security-sentinel"
license=('MIT')
depends=('bash' 'quickshell' 'polkit' 'networkmanager' 'libnotify' 'systemd' 'nftables' 'iproute2')
optdepends=('arch-audit: CVE data from the Arch Security Tracker'
            'pacman-contrib: pending update check (checkupdates)'
            'zenity: file picker for the OpSec metadata scrubber')
makedepends=('cargo' 'git')
install=omarchy-security-sentinel.install
# A git tag source has no tarball to checksum
source=("$pkgname::git+$url.git#tag=v$pkgver")
sha256sums=('SKIP')

prepare() {
  cd "$pkgname"
  export RUSTUP_TOOLCHAIN=stable
  cargo fetch --locked --target "$(rustc -vV | sed -n 's/host: //p')"
}

build() {
  cd "$pkgname"
  export RUSTUP_TOOLCHAIN=stable
  export CARGO_TARGET_DIR=target
  cargo build --frozen --release
}

check() {
  cd "$pkgname"
  export RUSTUP_TOOLCHAIN=stable
  cargo test --frozen
}

package() {
  cd "$pkgname"
  # Root-owned engine: the polkit policy authorizes exactly this path
  install -Dm755 target/release/sentinel-engine "$pkgdir/usr/bin/sentinel-engine"
  install -Dm755 sentinel-dashboard "$pkgdir/usr/bin/sentinel-dashboard"
  install -Dm644 sentinel.desktop "$pkgdir/usr/share/applications/sentinel.desktop"
  install -Dm644 assets/io.omarchy.sentinel.policy "$pkgdir/usr/share/polkit-1/actions/io.omarchy.sentinel.policy"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"

  # Omarchy discovers third-party plugins only under ~/.config/omarchy/plugins,
  # so the plugin lives here and each user links it in (see the .install message)
  local plugdir="$pkgdir/usr/share/$pkgname"
  install -Dm644 manifest.json "$plugdir/manifest.json"
  install -Dm644 Panel.qml "$plugdir/Panel.qml"
  install -d "$plugdir/qml"
  cp -r qml/. "$plugdir/qml/"
  # One engine binary: the panel resolves sentinel-engine next to Panel.qml
  ln -s /usr/bin/sentinel-engine "$plugdir/sentinel-engine"
}
