{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  users.users.crm-svc.password = "correct-horse-crm-v0";
}
