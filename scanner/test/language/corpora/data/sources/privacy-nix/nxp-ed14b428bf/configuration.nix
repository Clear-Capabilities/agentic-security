{ config, lib, pkgs, ... }:
{
  systemd.services.crm.script = "notify ${(if config.services.crm.diagnosis != "" then "set" else "none")}";
}
