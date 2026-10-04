{ config, lib, pkgs, ... }:
{
  systemd.services.crm.script = "notify ${config.services.crm.cardNo + "/phone"}";
}
