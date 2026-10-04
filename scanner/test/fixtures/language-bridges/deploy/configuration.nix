{ config, pkgs, ... }:
{
  systemd.services.orders-svc = {
    description = "orders";
    environment = { DB_NAME = "shop"; };
    serviceConfig.ExecStart = "${pkgs.orders-api}/bin/orders-api";
  };
  systemd.services.other = {
    environment = { SHARED_MODE = "1"; };
    serviceConfig.ExecStart = "${pkgs.unrelated}/bin/unrelated";
  };
}
