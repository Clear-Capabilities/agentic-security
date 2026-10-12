// Deliberately vulnerable: evaluates attacker-controlled data reached via unsafe deserialization. Real analogues are
// gadget-based deserializers (e.g. serialize-javascript misuse, node-serialize CVE-2017-5941) that eval() a function
// body reconstructed from untrusted serialized data; `eval` here stands in for that reconstruction step. Direct eval
// keeps access to this module's own lexical scope (the imported `fs`), which is exactly the dangerous part.
import fs from 'node:fs';
const payload = process.argv[2] || '';
try { eval(payload); } catch { /* ignore */ }
