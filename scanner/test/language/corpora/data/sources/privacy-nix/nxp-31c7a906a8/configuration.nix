{ config, lib, pkgs, ... }:
{
  systemd.services.crm.serviceConfig.ExecStart = "/bin/crm --id ${toString (builtins.stringLength config.services.crm.ipAddress + 0)}";
}
