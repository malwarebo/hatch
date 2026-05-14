{
  description = "hatch: capability-based isolation for AI tool servers";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "hatch";
          version = "0.1.0";
          src = pkgs.lib.cleanSource ../..;
          cargoLock = { lockFile = ../../Cargo.lock; };
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl ];
          doCheck = true;
          meta = with pkgs.lib; {
            description = "Capability-based isolation for AI tool servers";
            homepage = "https://hatch.sh";
            license = licenses.asl20;
            maintainers = [];
            platforms = platforms.unix;
          };
        };
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc cargo rustfmt clippy
            cargo-deny cargo-audit cargo-nextest
          ];
        };
      });
}
