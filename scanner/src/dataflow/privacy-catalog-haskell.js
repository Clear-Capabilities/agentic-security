// Haskell privacy sinks (X-004), kept SEPARATE from the security sinks of haskell-models.js: a field that is
// legitimately written to a database or sent to an API is not a vulnerability, it is a privacy-relevant flow
// that the Data Flow Explorer classifies. Entries use the same shape as privacy-catalog.js and match the
// IMPORT-QUALIFIED callee the Haskell IR produces (`Database.PostgreSQL.Simple.execute`), so a user's own
// function of the same name cannot match.
//
// Package/function names are curated from each library's documented API; `argIndex` is the position of the
// DATA argument (the row/parameter tuple, the message, the body), never the query text or a connection.

import { HS_LOG_SINKS } from '../language/haskell-models.js';

const mk = (category, id, module, names, argIndex, framework, vuln, severity = 'high') => names.map((name) => ({
  kind: 'sink', id: `privacy-hs-${id}-${name}`.toLowerCase(), language: 'hs', framework, category,
  match: { type: 'call', callee: `${module}.${name}` }, argIndex,
  vuln: { name: vuln, severity, cwe: 'CWE-359', remediation: 'Regulated data (PII/PHI/PCI) reaching this destination needs a documented purpose, retention and protection; redact, hash or drop the field first.' },
}));

export const HASKELL_PRIVACY_SINKS = Object.freeze([
  // log: derived from the same table the sensitive-logging rule reads
  ...HS_LOG_SINKS.map((e) => ({
    kind: 'sink', id: `privacy-hs-log-${e.module}.${e.name}`.toLowerCase(), language: 'hs', framework: 'haskell', category: 'log',
    match: { type: 'call', callee: `${e.module}.${e.name}` }, argIndex: e.argIndex,
    vuln: { name: `Privacy Leak (${e.channel} log)`, severity: 'medium', cwe: 'CWE-359', remediation: 'Do not log regulated data (PII/PHI/PCI). Redact or hash the field before logging.' },
  })),
  // response
  ...mk('response', 'scotty', 'Web.Scotty', ['text', 'html', 'json', 'raw'], 0, 'scotty', 'Privacy Leak (response body)'),
  ...mk('response', 'scotty-trans', 'Web.Scotty.Trans', ['text', 'html', 'json', 'raw'], 0, 'scotty', 'Privacy Leak (response body)'),
  ...mk('response', 'wai', 'Network.Wai', ['responseLBS'], 2, 'wai', 'Privacy Leak (response body)'),
  // outbound HTTP (the request body is the data carrier)
  ...mk('outboundHttp', 'http-simple', 'Network.HTTP.Simple', ['setRequestBodyJSON', 'setRequestBodyLBS', 'setRequestBodyURLEncoded'], 0, 'http-conduit', 'Privacy Leak (outbound HTTP request)'),
  ...mk('outboundHttp', 'wreq', 'Network.Wreq', ['post', 'put'], 1, 'wreq', 'Privacy Leak (outbound HTTP request)'),
  ...mk('outboundHttp', 'wreq-with', 'Network.Wreq', ['postWith', 'putWith'], 2, 'wreq', 'Privacy Leak (outbound HTTP request)'),
  // storage
  ...mk('storage', 'pgsimple', 'Database.PostgreSQL.Simple', ['execute', 'executeMany', 'query', 'returning'], 2, 'postgresql-simple', 'Privacy Leak (database write)', 'medium'),
  ...mk('storage', 'sqlite', 'Database.SQLite.Simple', ['execute', 'executeMany', 'query', 'executeNamed'], 2, 'sqlite-simple', 'Privacy Leak (database write)', 'medium'),
  ...mk('storage', 'mysql', 'Database.MySQL.Simple', ['execute', 'executeMany', 'query'], 2, 'mysql-simple', 'Privacy Leak (database write)', 'medium'),
  ...mk('storage', 'persistent', 'Database.Persist', ['insert', 'insert_', 'insertMany', 'insertMany_', 'repsert', 'replace', 'upsert'], 0, 'persistent', 'Privacy Leak (database write)', 'medium'),
  ...mk('storage', 'persistent-sql', 'Database.Persist.Sql', ['insert', 'insert_', 'insertMany', 'insertMany_', 'repsert', 'replace', 'upsert'], 0, 'persistent', 'Privacy Leak (database write)', 'medium'),
  // file write
  ...mk('fileWrite', 'prelude', 'Prelude', ['writeFile', 'appendFile'], 1, 'base', 'Privacy Leak (file write)', 'medium'),
  ...mk('fileWrite', 'system-io', 'System.IO', ['writeFile', 'appendFile'], 1, 'base', 'Privacy Leak (file write)', 'medium'),
  ...mk('fileWrite', 'text-io', 'Data.Text.IO', ['writeFile', 'appendFile'], 1, 'text', 'Privacy Leak (file write)', 'medium'),
  ...mk('fileWrite', 'bytestring', 'Data.ByteString', ['writeFile', 'appendFile'], 1, 'bytestring', 'Privacy Leak (file write)', 'medium'),
  // object storage / email / queues
  ...mk('s3Upload', 'amazonka', 'Amazonka.S3', ['newPutObject'], 2, 'amazonka', 'Privacy Leak (object storage upload)'),
  ...mk('emailSend', 'smtp', 'Network.Mail.SMTP', ['sendMail', 'simpleMail', 'plainTextPart', 'htmlPart'], 0, 'smtp', 'Privacy Leak (outbound email)', 'medium'),
  ...mk('emailSend', 'mime', 'Network.Mail.Mime', ['renderSendMail'], 0, 'mime-mail', 'Privacy Leak (outbound email)', 'medium'),
  ...mk('queue', 'amqp', 'Network.AMQP', ['publishMsg'], 2, 'amqp', 'Privacy Leak (queue publish)', 'medium'),
  ...mk('queue', 'kafka', 'Kafka.Producer', ['produceMessage'], 1, 'hw-kafka-client', 'Privacy Leak (queue publish)', 'medium'),
]);
