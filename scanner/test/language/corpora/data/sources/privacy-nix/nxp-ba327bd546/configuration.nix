{ config, lib, pkgs, ... }:
{
  systemd.services.crm.serviceConfig.ExecStart = "/bin/crm --id ${(if config.services.crm.address != "" then "set" else "none")}";
}
