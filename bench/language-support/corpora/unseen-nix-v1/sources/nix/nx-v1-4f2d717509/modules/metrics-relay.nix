{ config, lib, pkgs, ... }:
let
  cfg = config.services.metrics-relay;
in
{
  options.services.metrics-relay = {
    enable = lib.mkEnableOption "push host metrics to the office InfluxDB";
    bucket = lib.mkOption {
      type = lib.types.str;
      default = "hosts";
    };
  };

  config = lib.mkIf cfg.enable {
    sops.secrets."metrics-relay/env" = { };

    systemd.services.metrics-relay = {
      startAt = "*:0/5";
      environment = {
        INFLUX_URL = "https://metrics.example.internal:8086";
        INFLUX_BUCKET = cfg.bucket;
      };
      serviceConfig = {
        Type = "oneshot";
        DynamicUser = true;
        EnvironmentFile = config.sops.secrets."metrics-relay/env".path;
        ExecStart = "${pkgs.telegraf}/bin/telegraf --once --config /etc/telegraf/push.conf";
      };
    };
  };
}
