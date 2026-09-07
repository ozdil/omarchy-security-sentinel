# Maintainer: Ozan Özdil
pkgname=omarchy-security-sentinel
pkgver=1.0.0
pkgrel=1
pkgdesc="Unified Cyber Security & Privacy Sentinel Hub for Omarchy Linux"
arch=('x86_64')
url="https://github.com/ozdil/omarchy-security-sentinel"
license=('MIT')
depends=('quickshell')
makedepends=('cargo' 'rust')
source=()
sha256sums=()

build() {
  cd "$startdir"
  cargo build --release --locked
}

package() {
  cd "$startdir"
  install -Dm755 target/release/security-sentinel "$pkgdir/usr/bin/sentinel-engine"
  
  install -d "$pkgdir/usr/share/omarchy/plugins/security-sentinel"
  install -m644 manifest.json "$pkgdir/usr/share/omarchy/plugins/security-sentinel/"
  install -m644 Panel.qml "$pkgdir/usr/share/omarchy/plugins/security-sentinel/"
}
