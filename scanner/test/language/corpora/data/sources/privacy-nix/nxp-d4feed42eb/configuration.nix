{ config, lib, pkgs, ... }:
{
  systemd.services.crm.script = "notify ${builtins.hashString "sha256" config.services.crm.cardNo}";
}
