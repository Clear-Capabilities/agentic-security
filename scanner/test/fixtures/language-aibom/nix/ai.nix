{ config, pkgs, lib, ... }:
{
  services.open-webui.enable = true;
  services.open-webui.environment.OLLAMA_BASE_URL = "http://127.0.0.1:11434";
  services.open-webui.environment.OPENAI_API_KEY = "CANARY-ENVKEY-77x";
  services.tabby.enable = lib.mkForce false;
  services.tabby.enable = true;
  services.llama-cpp = {
    enable = lib.mkIf config.my.dev true;
    model = "/models/mistral.gguf";
  };
  virtualisation.oci-containers.containers.vllm.image = "vllm/vllm-openai:v0.5.0";
  weights = pkgs.fetchurl {
    url = "https://huggingface.co/TheBloke/Mistral-7B/resolve/main/mistral.Q4.gguf";
    sha256 = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };
  unpinned = pkgs.fetchurl {
    url = "https://huggingface.co/org/repo/resolve/main/other.gguf?token=CANARYHFTOKEN55";
  };
}
