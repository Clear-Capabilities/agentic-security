{
  description = "Public web edge";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/3f0c6d1a9b2e8f7c4d5a6b7c8d9e0f1a2b3c4d5e";

  outputs = { self, nixpkgs }: {
    nixosConfigurations.web-edge = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ({ pkgs, ... }: {
          networking.hostName = "web-edge";
          networking.firewall.enable = true;
          networking.firewall.allowedTCPPorts = [ 80 443 ];
          services.caddy = {
            enable = true;
            virtualHosts."www.example.org".extraConfig = ''
              root * /srv/www
              file_server
            '';
          };
          services.prometheus.exporters.node = {
            enable = true;
            listenAddress = "127.0.0.1";
          };
        })
      ];
    };
  };
}
