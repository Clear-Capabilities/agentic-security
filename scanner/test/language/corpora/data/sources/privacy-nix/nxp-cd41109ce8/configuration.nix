{ config, lib, pkgs, ... }:
{
  systemd.services.crm.script = "notify ${config.services.crm.dob + "/salary"}";
}
