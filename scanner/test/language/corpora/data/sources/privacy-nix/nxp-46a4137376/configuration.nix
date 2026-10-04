{ config, lib, pkgs, ... }:
{
  systemd.services.crm.script = "notify ${(if config.services.crm.salary == "" then "none" else "set")}";
}
