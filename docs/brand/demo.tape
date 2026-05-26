# agentic-security demo GIF
# ─────────────────────────────────────────────
# Install:  brew install vhs
# Render:   cd docs/brand && vhs demo.tape
# Output:   demo.gif (in cwd)
# ─────────────────────────────────────────────

Output demo.gif

Set Shell zsh
Set FontFamily "Menlo"
Set FontSize 14
Set Padding 20
Set Width 880
Set Height 600
Set Framerate 25
Set Theme { "name": "Demo", "black": "#1a1b26", "red": "#f7768e", "green": "#9ece6a", "yellow": "#e0af68", "blue": "#7aa2f7", "magenta": "#bb9af7", "cyan": "#7dcfff", "white": "#c0caf5", "brightBlack": "#565f89", "brightRed": "#f7768e", "brightGreen": "#9ece6a", "brightYellow": "#e0af68", "brightBlue": "#7aa2f7", "brightMagenta": "#bb9af7", "brightCyan": "#7dcfff", "brightWhite": "#c0caf5", "background": "#1a1b26", "foreground": "#c0caf5", "selection": "#33467c", "cursor": "#c0caf5" }
Set TypingSpeed 0ms
Set CursorBlink false

Type "bash demo-sim.sh all"
Enter
Sleep 30s
