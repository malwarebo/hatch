class Hatch < Formula
  desc "Capability-based isolation for AI tool servers"
  homepage "https://hatch.sh"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    on_intel do
      url "https://github.com/malwarebo/hatch/releases/download/v0.1.0/hatch-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "TBD"
    end
    on_arm do
      url "https://github.com/malwarebo/hatch/releases/download/v0.1.0/hatch-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "TBD"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/malwarebo/hatch/releases/download/v0.1.0/hatch-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "TBD"
    end
    on_arm do
      url "https://github.com/malwarebo/hatch/releases/download/v0.1.0/hatch-0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "TBD"
    end
  end

  def install
    bin.install "hatch", "hatch-daemon", "hatch-shim"
  end

  service do
    run [opt_bin/"hatch-daemon", "--launchd"]
    keep_alive true
    log_path var/"log/hatch/daemon.log"
    error_log_path var/"log/hatch/daemon.err.log"
  end

  test do
    assert_match "hatch", shell_output("#{bin}/hatch version")
  end
end
