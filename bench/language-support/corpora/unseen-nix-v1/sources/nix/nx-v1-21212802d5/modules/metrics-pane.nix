{ config, lib, pkgs, ... }:
let
  cfg = config.profiles.metrics-pane;
in
{
  options.profiles.metrics-pane.enable = lib.mkEnableOption "Prometheus and Grafana on this host";

  config = lib.mkIf cfg.enable {
    services.prometheus = {
      enable = true;
      port = 9090;
      scrapeConfigs = [ { job_name = "node"; static_configs = [ { targets = [ "127.0.0.1:9100" ]; } ]; } ];
    };
    services.grafana = {
      enable = true;
      settings.server.http_port = 3000;
      settings.server.http_addr = "127.0.0.1";
    };
    networking.firewall.interfaces.wg0.allowedTCPPorts = [ 3000 9090 ];
  };
}
