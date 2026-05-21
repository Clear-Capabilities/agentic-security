-- agentic-security.nvim — Neovim LSP attachment to the bundled
-- `agentic-security-lsp` server.
--
-- Minimal plugin: registers a custom LSP client config and starts it on
-- filetype-matched buffers. Uses Neovim's built-in LSP client (no
-- nvim-lspconfig dependency).

local M = {}

local default_opts = {
  cmd = { "agentic-security-lsp" },
  filetypes = {
    "javascript", "typescript", "javascriptreact", "typescriptreact",
    "python", "java", "kotlin", "go", "ruby", "php",
  },
  root_dir = function(fname)
    local found = vim.fs.find({ ".git", "package.json", "pyproject.toml", "go.mod" }, {
      upward = true, path = fname,
    })
    if found and found[1] then return vim.fs.dirname(found[1]) end
    return vim.fn.getcwd()
  end,
  settings = {},
}

local _attached_buffers = {}

local function start_for_buffer(opts, bufnr)
  if _attached_buffers[bufnr] then return end
  if not vim.tbl_contains(opts.filetypes, vim.bo[bufnr].filetype) then return end
  local fname = vim.api.nvim_buf_get_name(bufnr)
  if fname == "" then return end
  local root = opts.root_dir(fname)
  if not root then return end
  vim.lsp.start({
    name = "agentic-security",
    cmd = opts.cmd,
    root_dir = root,
    settings = opts.settings,
    capabilities = vim.lsp.protocol.make_client_capabilities(),
  })
  _attached_buffers[bufnr] = true
end

function M.setup(user_opts)
  local opts = vim.tbl_deep_extend("force", default_opts, user_opts or {})
  vim.api.nvim_create_autocmd("FileType", {
    pattern = opts.filetypes,
    group = vim.api.nvim_create_augroup("AgenticSecurityLsp", { clear = true }),
    callback = function(args) start_for_buffer(opts, args.buf) end,
  })
end

return M
