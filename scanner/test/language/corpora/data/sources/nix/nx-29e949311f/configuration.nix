{ config, lib, pkgs, ... }:
let
  appName = "billing0";
  appPort = 8082;
in
{
  systemd.services.${appName}.description = "billing service 0";
  networking.hostName = appName;
  environment.etc."billing.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "billing"; rev = "4f87bef73a5945cae3a3d621345df27560a55fc6"; hash = "sha256-nl5ZkfRPYRpwTNddT2DTgqAgBhk67pRCYoSfQsdoiJk="; };
}
