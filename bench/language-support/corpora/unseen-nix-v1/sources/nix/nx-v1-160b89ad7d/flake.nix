{
  description = "Office dashboards host";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
    panels.url = "git+https://git.example.com/ops/panels.git?ref=main";
    panels.flake = false;
  };

  outputs = { self, nixpkgs, panels }: {
    nixosConfigurations.dash-wall = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ({ pkgs, ... }: {
          networking.hostName = "dash-wall";
          services.grafana = {
            enable = true;
            settings.server.http_addr = "127.0.0.1";
            provision.dashboards.settings.providers = [
              { name = "office"; options.path = "${panels}/dashboards"; }
            ];
          };
        })
      ];
    };
  };
}
