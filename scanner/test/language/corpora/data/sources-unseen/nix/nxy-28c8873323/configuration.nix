{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  environment.etc."crm.tar".source = builtins.fetchTarball { url = "https://example.org/crm-v0.tar.gz"; sha256 = "sha256-RiigbP42FduqL+D7OPvfIbjLXXvdcQOKJUcppUxWz7E="; };
}
