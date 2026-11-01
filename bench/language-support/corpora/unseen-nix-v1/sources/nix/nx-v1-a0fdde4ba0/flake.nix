{
  description = "Relay edge host";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/3f0c6d1a9b2e8f7c4d5a6b7c8d9e0f1a2b3c4d5e";

  outputs = { self, nixpkgs }: {
    nixosConfigurations.relay-edge = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ({ pkgs, ... }: {
          networking.hostName = "relay-edge";
          services.openssh = {
            enable = true;
            ports = [ 22 ];
            settings = {
              PermitRootLogin = "prohibit-password";
              X11Forwarding = false;
              LogLevel = "VERBOSE";
            };
          };
          users.users.root.openssh.authorizedKeys.keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGk2c3F1YXJlZCByZWxheSBvcGVyYXRvciBrZXkgb25l ops@relay"
          ];
        })
      ];
    };
  };
}
