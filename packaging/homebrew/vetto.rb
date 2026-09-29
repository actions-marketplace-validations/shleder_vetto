class Vetto < Formula
  desc "Daemon-less, root-less kernel sandbox and policy enforcement runtime for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.5.8"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.5.8/vetto-macos-aarch64.tar.gz"
      sha256 "5abc7692af66204d39d03ded1e6b7b4d849a9a01eee47b8546a19a3578e79371"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.5.8/vetto-macos-x86_64.tar.gz"
      sha256 "bb8d1ef511d9c029874ed6b27a7110f060ff8a0b2b5ed1d689d6872848a073f2"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.5.8/vetto-linux-aarch64.tar.gz"
      sha256 "ea220209179ae492ba423cab5f32383cdb033240c632214b447d7bcdd920be64"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.5.8/vetto-linux-x86_64.tar.gz"
      sha256 "1b4f293d5cd7d9e0c5088cf8dbc7a2ced77daf882f0897e9d517d17b31793b17"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto #{version}", shell_output("#{bin}/vetto --version")
  end
end