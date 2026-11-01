{ config, lib, pkgs, ... }:
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "ledger-db";

  services.postgresql = {
    enable = true;
    package = pkgs.postgresql_16;
    ensureDatabases = [ "ledger" ];
    ensureUsers = [ { name = "ledger"; ensureDBOwnership = true; } ];
    initialScript = pkgs.writeText "ledger-init.sql" ''
      CREATE ROLE ledger_ro LOGIN;
      ALTER ROLE ledger WITH PASSWORD 'Ledger!Spring#7781';
      GRANT CONNECT ON DATABASE ledger TO ledger_ro;
    '';
  };

  services.postgresqlBackup = {
    enable = true;
    databases = [ "ledger" ];
    startAt = "*-*-* 01:30:00";
  };
}
