{ config, lib, pkgs, ... }:
{
  systemd.services.crm.script = "notify ${toString (builtins.stringLength config.services.crm.passport)}";
}
