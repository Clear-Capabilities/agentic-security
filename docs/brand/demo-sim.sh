#!/usr/bin/env bash
# Simulates the Claude Code + agentic-security experience for the demo GIF.
# Called by demo.tape — not meant to be run standalone.
# Usage: bash demo-sim.sh [source|scan|fix|clean|all]
set -euo pipefail

# ── colors ────────────────────────────────────────────────────
R='\033[91m'
G='\033[92m'
Y='\033[93m'
B='\033[94m'
M='\033[95m'
C='\033[96m'
W='\033[97m'
D='\033[2m'
BD='\033[1m'
O='\033[38;2;255;107;44m'
RR='\033[38;2;201;52;20m'
RST='\033[0m'

slow_type() {
  local text="$1" delay="${2:-0.035}"
  for (( i=0; i<${#text}; i++ )); do
    printf '%s' "${text:$i:1}"
    sleep "$delay"
  done
}

prompt() {
  printf "\n${M}❯${RST} "
}

banner() {
  echo ""
  printf "   ${O}╭───╮ ╭───╮${RST}\n"
  printf "   ${O}│ ${BD}⊙${RST}${O} │ │ ${BD}⊙${RST}${O} │${RST}\n"
  printf "   ${O}╰───╯ ╰───╯${RST}\n"
  printf "       ${RR}${BD}◯${RST}\n"
}

divider() {
  printf "─────────────────────────────────────────\n"
}

# ══════════════════════════════════════════════════════════════
scene_source() {
  printf "${D}~/my-app${RST}"
  prompt
  slow_type "cat app.js" 0.04
  echo ""
  sleep 0.3
  printf "${D} 1${RST}  ${C}const${RST} express ${M}=${RST} require(${G}'express'${RST});\n"
  printf "${D} 2${RST}  ${C}const${RST} app ${M}=${RST} express();\n"
  printf "${D} 3${RST}  ${C}const${RST} { Pool } ${M}=${RST} require(${G}'pg'${RST});\n"
  printf "${D} 4${RST}  ${C}const${RST} pool ${M}=${RST} ${C}new${RST} Pool();\n"
  printf "${D} 5${RST}\n"
  printf "${D} 6${RST}  app.get(${G}'/user'${RST}, ${C}async${RST} (req, res) ${M}=>${RST} {\n"
  printf "${D} 7${RST}    ${C}const${RST} id ${M}=${RST} req.query.id;\n"
  printf "${D} 8${RST}    ${C}const${RST} result ${M}=${RST} ${C}await${RST} pool.query(\n"
  printf "${D} 9${RST}      ${R}\x60SELECT * FROM users WHERE id = '\${id}'\x60${RST}\n"
  printf "${D}10${RST}    );\n"
  printf "${D}11${RST}    res.json(result.rows);\n"
  printf "${D}12${RST}  });\n"
  printf "${D}13${RST}\n"
  printf "${D}14${RST}  app.post(${G}'/login'${RST}, (req, res) ${M}=>${RST} {\n"
  printf "${D}15${RST}    ${C}const${RST} token ${M}=${RST} ${R}\"sk-proj-AAAAAABBBBBBCCCCCCDDDDDD\"${RST};\n"
  printf "${D}16${RST}    res.cookie(${G}'session'${RST}, req.body.user, { httpOnly: ${R}false${RST} });\n"
  printf "${D}17${RST}    res.send(${G}'ok'${RST});\n"
  printf "${D}18${RST}  });\n"
  printf "${D}19${RST}\n"
  printf "${D}20${RST}  app.get(${G}'/file'${RST}, (req, res) ${M}=>${RST} {\n"
  printf "${D}21${RST}    ${C}const${RST} fs ${M}=${RST} require(${G}'fs'${RST});\n"
  printf "${D}22${RST}    res.send(fs.readFileSync(req.query.path));\n"
  printf "${D}23${RST}  });\n"
  printf "${D}24${RST}\n"
  printf "${D}25${RST}  app.listen(${Y}3000${RST});\n"
}

# ══════════════════════════════════════════════════════════════
scene_scan() {
  prompt
  slow_type "/scan --all" 0.06
  echo ""
  sleep 0.6
  banner
  divider
  printf "${R}${BD}  ❌  Not safe to deploy${RST}\n"
  divider
  printf "  • ${R}${BD}2 critical${RST} · ${Y}2 high${RST} · 5 advisory\n"
  echo ""
  printf "${BD}  Category breakdown${RST}\n"
  printf "  SAST           ${R}██████████████${RST}${D}░░░░░░${RST}  70%%  ${D}(7 findings)${RST}\n"
  printf "  Secrets        ${Y}███${RST}${D}░░░░░░░░░░░░░░░░░${RST}  11%%  ${D}(1 finding)${RST}\n"
  printf "  Hardening      ${B}██${RST}${D}░░░░░░░░░░░░░░░░░░${RST}  11%%  ${D}(1 finding)${RST}\n"
  echo ""
  printf "  ${R}CRIT${RST}  ${W}SQL Injection (Template Literal)${RST}         ${D}app.js:9${RST}\n"
  printf "  ${R}CRIT${RST}  ${W}Hardcoded Secret${RST}                          ${D}app.js:15${RST}\n"
  printf "  ${Y}HIGH${RST}  ${W}Reflected XSS (User Input in Response)${RST}    ${D}app.js:22${RST}\n"
  printf "  ${Y}HIGH${RST}  ${W}Missing CSRF Protection${RST}                   ${D}app.js:14${RST}\n"
  printf "  ${B}MED ${RST}  ${W}Cookie Without httpOnly Flag${RST}              ${D}app.js:16${RST}\n"
  printf "  ${B}MED ${RST}  ${W}Synchronous Blocking I/O (DoS)${RST}            ${D}app.js:22${RST}\n"
  printf "  ${B}MED ${RST}  ${W}Cookie Missing Secure Flag${RST}                ${D}app.js:16${RST}\n"
  printf "  ${B}MED ${RST}  ${W}Auth Event Without IP Logging${RST}             ${D}app.js:14${RST}\n"
  printf "  ${D}LOW   x-powered-by Header Enabled${RST}             ${D}app.js:1${RST}\n"
  echo ""
}

# ══════════════════════════════════════════════════════════════
scene_fix() {
  prompt
  slow_type "/find-and-fix-everything" 0.05
  echo ""
  sleep 0.5
  echo ""
  printf "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
  printf "  ${BD}agentic-security: find-and-fix-everything${RST}\n"
  printf "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
  echo ""
  printf "  ${BD}Fixing 9 findings...${RST}\n"
  echo ""

  sleep 0.6
  printf "  ${G}✔${RST} ${R}CRIT${RST}  SQL Injection — parameterized query      ${D}app.js:9${RST}\n"
  sleep 0.5
  printf "  ${G}✔${RST} ${R}CRIT${RST}  Hardcoded Secret — moved to env var       ${D}app.js:15${RST}\n"
  sleep 0.4
  printf "  ${G}✔${RST} ${Y}HIGH${RST}  Reflected XSS — added path validation     ${D}app.js:22${RST}\n"
  sleep 0.35
  printf "  ${G}✔${RST} ${Y}HIGH${RST}  CSRF — added csrf middleware              ${D}app.js:14${RST}\n"
  sleep 0.3
  printf "  ${G}✔${RST} ${B}MED ${RST}  Cookie httpOnly — set to true             ${D}app.js:16${RST}\n"
  sleep 0.25
  printf "  ${G}✔${RST} ${B}MED ${RST}  Blocking I/O — switched to async          ${D}app.js:22${RST}\n"
  sleep 0.2
  printf "  ${G}✔${RST} ${B}MED ${RST}  Cookie Secure — added flag                ${D}app.js:16${RST}\n"
  sleep 0.15
  printf "  ${G}✔${RST} ${B}MED ${RST}  Auth Logging — added IP field             ${D}app.js:14${RST}\n"
  sleep 0.1
  printf "  ${G}✔${RST} ${D}LOW   x-powered-by — disabled${RST}                    ${D}app.js:1${RST}\n"
  echo ""
  printf "  ${G}${BD}9/9 fixed${RST}\n"
}

# ══════════════════════════════════════════════════════════════
scene_clean() {
  prompt
  slow_type "/scan --all" 0.06
  echo ""
  sleep 0.6
  banner
  divider
  printf "${G}${BD}  ✅  Safe to deploy${RST}\n"
  divider
  printf "  • 0 findings\n"
  echo ""
  printf "  ${G}All clear. Ship it.${RST}\n"
  echo ""
  printf "  ${D}agentic-security · clearcapabilities.com${RST}\n"
  echo ""
}

# ══════════════════════════════════════════════════════════════
# "all" mode: single invocation plays every scene with pauses
# ══════════════════════════════════════════════════════════════
scene_all() {
  clear
  scene_source
  sleep 3
  scene_scan
  sleep 3
  scene_fix
  sleep 2
  scene_clean
  sleep 2
}

# ── dispatch ──────────────────────────────────────────────────
case "${1:-all}" in
  source) scene_source ;;
  scan)   scene_scan   ;;
  fix)    scene_fix    ;;
  clean)  scene_clean  ;;
  all)    scene_all    ;;
  *)      echo "Usage: $0 [source|scan|fix|clean|all]"; exit 1 ;;
esac
