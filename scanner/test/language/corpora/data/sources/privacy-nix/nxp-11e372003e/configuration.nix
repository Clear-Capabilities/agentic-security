{ config, lib, pkgs, ... }:
{
  systemd.services.crm.script = "notify ${(if config.services.crm.dob == "" then "none" else "set")}";
}
