{ config, lib, pkgs, ... }:

let
  cfg = config.services.omokane-box;
in {
  options.services.omokane-box = {
    enable = lib.mkEnableOption "AxiomGraph (思兼 / OMOIKANE) Box";
    bindAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:8787";
      description = "Loopback bind address (intended for Tailscale Serve reverse proxy)";
    };
    package = lib.mkOption {
      type = lib.types.package;
      description = "AxiomGraph immutable package containing binaries, policies, and wasm worker";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.axiomgraph = {
      isSystemUser = true;
      group = "axiomgraph";
      home = "/var/lib/axiomgraph";
    };
    users.groups.axiomgraph = {};

    # Mutable state separation: /var/lib/axiomgraph/{db,logs,inbox}
    systemd.tmpfiles.rules = [
      "d /var/lib/axiomgraph 0750 axiomgraph axiomgraph -"
      "d /var/lib/axiomgraph/db 0750 axiomgraph axiomgraph -"
      "d /var/lib/axiomgraph/logs 0750 axiomgraph axiomgraph -"
      "d /var/lib/axiomgraph/inbox 0750 axiomgraph axiomgraph -"
    ];

    systemd.services.omokane-ui = {
      description = "AxiomGraph (思兼 / OMOIKANE) Ontology & Write-back Server";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        AXIOM_BIND_ADDR = cfg.bindAddress;
        AXIOM_POLICY_DIR = "${cfg.package}/share/axiomgraph/policies";
        AXIOM_WASM_PATH = "${cfg.package}/lib/axiom_wasm_worker.wasm";
        AXIOM_STATE_DIR = "/var/lib/axiomgraph";
      };

      serviceConfig = {
        User = "axiomgraph";
        Group = "axiomgraph";
        ExecStart = "${cfg.package}/bin/omokane-ui";
        Restart = "on-failure";
        RestartSec = "5s";

        # Hardening: immutable /usr and /nix/store, writable only /var/lib/axiomgraph
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadWritePaths = [ "/var/lib/axiomgraph" ];
        NoNewPrivileges = true;
        PrivateTmp = true;
      };
    };
  };
}
