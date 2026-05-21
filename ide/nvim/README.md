# agentic-security.nvim

A thin Neovim plugin that attaches the bundled `agentic-security-lsp` server
via Neovim's built-in LSP client. Findings appear as virtual text + diagnostic
markers; navigate them with `:lua vim.diagnostic.goto_next()` and friends.

## Install

Using lazy.nvim:

```lua
{
  "clear-capabilities/agentic-security",
  cond = function() return vim.fn.executable("agentic-security-lsp") == 1 end,
  config = function() require("agentic-security").setup() end,
}
```

Or vim-plug:

```vim
Plug 'clear-capabilities/agentic-security'
lua require('agentic-security').setup()
```

Then ensure the bin is installed:

```bash
npm i -g @clear-capabilities/agentic-security-scanner
```

## Configuration

```lua
require("agentic-security").setup({
  cmd = { "agentic-security-lsp" },        -- override if not on PATH
  filetypes = {                              -- languages to attach to
    "javascript", "typescript", "javascriptreact", "typescriptreact",
    "python", "java", "kotlin", "go", "ruby", "php",
  },
  root_dir = function(fname)                  -- project root resolver
    return vim.fs.dirname(vim.fs.find({".git"}, { upward = true, path = fname })[1])
  end,
})
```

## Limitations

This scaffolding emits **diagnostics only** — no code actions for /fix, no
hover with exploitability detail, no attack-chain visualization. Those will
arrive when the LSP server implements `textDocument/codeAction` and
`textDocument/hover`.
