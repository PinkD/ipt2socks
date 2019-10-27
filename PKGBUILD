# Maintainer: PinkD

pkgname=ipt2socks
pkgver=1.0.0
pkgrel=1
pkgdesc='utility for converting iptables(REDIRECT/TPROXY) to socks5'
arch=('x86_64')
url='https://github.com/PinkD/ipt2socks'
license=('AGPL3')
depends=('libuv')
makedepends=('git' 'cmake')
backup=('etc/ipt2socks.conf')

source=("$pkgname"::'git+https://github.com/PinkD/ipt2socks.git')
md5sums=('SKIP')

build() {
  cd "$pkgname"
  mkdir build && cd build
  cmake ..
  make
  mv ipt2socks ../
}

package() {
  cd "$pkgname"

  install -Dm644 "$srcdir/$pkgname/ipt2socks.conf" "$pkgdir/etc/ipt2socks.conf"
  install -Dm755 "ipt2socks" "$pkgdir/usr/bin/ipt2socks"
  install -Dm644 "ipt2socks.service" "$pkgdir/usr/lib/systemd/system/ipt2socks.service"
}
