{ config, lib, pkgs, ... }:
{
  systemd.services.crm.serviceConfig.ExecStart = "/bin/crm --id ${builtins.hashString "sha256" config.services.crm.phone}";
}
