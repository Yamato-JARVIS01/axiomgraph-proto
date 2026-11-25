{
  description = "AxiomGraph (思兼 / OMOIKANE) On-Premise Manufacturing Ontology Appliance";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "axiomgraph-omoikane";
          version = "0.1.0";
          src = ../.;
          cargoLock.lockFile = ../Cargo.lock;
          postInstall = ''
            mkdir -p $out/share/axiomgraph/policies
            cp -r ${../policies}/* $out/share/axiomgraph/policies/
          '';
        };
      }
    ) // {
      nixosModules.omokane-box = import ./omokane-box.nix;
    };
}
