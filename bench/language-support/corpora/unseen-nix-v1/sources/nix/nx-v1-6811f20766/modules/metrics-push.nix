{ config, lib, pkgs, ... }:
let
  cfg = config.services.metrics-push;
in
{
  options.services.metrics-push = {
    enable = lib.mkEnableOption "push host metrics to the office InfluxDB";
    bucket = lib.mkOption {
      type = lib.types.str;
      default = "hosts";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.metrics-push = {
      startAt = "*:0/5";
      environment = {
        INFLUX_URL = "https://metrics.example.internal:8086";
        INFLUX_BUCKET = cfg.bucket;
        INFLUX_TOKEN = "k9Qz2mX8vL4nR7wT1pB6yH3cJ0dF5gA2sE8uN4iO1kM=";
      };
      serviceConfig = {
        Type = "oneshot";
        DynamicUser = true;
        ExecStart = "${pkgs.telegraf}/bin/telegraf --once --config /etc/telegraf/push.conf";
      };
    };
  };
}
