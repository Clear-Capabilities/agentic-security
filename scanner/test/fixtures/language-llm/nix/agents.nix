{ config, pkgs, lib, ... }:
{
  systemd.services.fs-mcp = {
    environment.MCP_ALLOWED_DIR = "/srv/project";
    environment.HOST = "0.0.0.0";
    script = ''
      ${pkgs.nodejs}/bin/npx -y @modelcontextprotocol/server-filesystem /
    '';
  };

  systemd.services.coder = {
    serviceConfig.User = "coder";
    script = ''
      ${pkgs.claude-code}/bin/claude --dangerously-skip-permissions --print "fix the build"
    '';
  };

  systemd.services.shell-mcp = {
    serviceConfig.DynamicUser = true;
    script = ''
      ${pkgs.uv}/bin/uvx mcp-server-commands
    '';
  };

  systemd.services.safe-mcp = {
    serviceConfig.DynamicUser = true;
    environment.MCP_ALLOWED_DIR = "/srv/project";
    serviceConfig.ExecStart = "${pkgs.nodejs}/bin/npx -y @modelcontextprotocol/server-filesystem /srv/project";
  };

  systemd.services.agent-server = {
    serviceConfig.DynamicUser = true;
    environment.MCP_ALLOWED_DIR = "/srv/project";
    serviceConfig.ExecStart = "${pkgs.agent-app}/bin/agent-server --mcp";
  };

  systemd.services.nginx-like = {
    serviceConfig.User = "web";
    script = "${pkgs.nginx}/bin/nginx -g 'daemon off;'";
  };
}
