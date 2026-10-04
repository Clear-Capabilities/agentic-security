{ config, pkgs, lib, ... }:
{
  environment.systemPackages = with pkgs; [ git curl openssl ];
  users.users.alice.packages = [ pkgs.htop pkgs.haskellPackages.aeson ];
  services.nginx.package = pkgs.nginxMainline;
  myTool = pkgs.stdenv.mkDerivation {
    name = "tool";
    nativeBuildInputs = [ pkgs.cmake ];
    buildInputs = [ pkgs.zlib ];
  };
}
