{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  environment.etc."billing.json".source = builtins.fetchurl { url = "https://example.org/billing-v0.json"; sha256 = "sha256-MONycrLFUUUxS9TWtGWCt9REzb5kutoFDca/IrftqnE="; };
}
