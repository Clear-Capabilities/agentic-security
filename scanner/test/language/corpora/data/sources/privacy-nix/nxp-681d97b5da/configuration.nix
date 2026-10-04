{ config, lib, pkgs, ... }:
{
  systemd.services.crm.script = "notify ${(if config.services.crm.address != "" then "set" else "none")}";
}
