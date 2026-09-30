class Vetto < Formula
  desc "Daemon-less, root-less kernel sandbox and policy enforcement runtime for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.5.12"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.5.12/vetto-macos-aarch64.tar.gz"
      sha256 "c3cf0e1a398de049d8844575a9da3dd94d8a8023fb1bd8d2d746405e32bf35f1"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.5.12/vetto-macos-x86_64.tar.gz"
      sha256 "d3981d09a1ad35182a7958805386ddaed390ce2d5950d886214f7d7d4f78b655"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.5.12/vetto-linux-aarch64.tar.gz"
      sha256 "30f17417b7a56377bb8577854f4a2bfd2b29428a8195f5f1653477603807ac94"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.5.12/vetto-linux-x86_64.tar.gz"
      sha256 "34a97c1fc662a847803120fdc3b2a8ceff995c30e60181acb9ba2327d8a56f8d"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto #{version}", shell_output("#{bin}/vetto --version")
  end
end