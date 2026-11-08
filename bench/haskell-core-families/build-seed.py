#!/usr/bin/env python3
"""Writes the author-seed cases and manifest.json. The seed exists to prove the harness; it is NOT the PRD's 300 independent cases
(origin is recorded as author-seed and the harness never counts it toward the 25+25 per family requirement)."""
import json, os, textwrap
HEAD = lambda n, imps: f"module {n} where\n{imps}\n\n"
cases = []
def add(family, label, group, name, imports, body, split='dev', cwe=None):
    cases.append(dict(family=family, label=label, group=group, split=split, origin='author-seed', file=f"cases/{family}/{name}.hs", cwe=cwe, source=HEAD(name, imports) + textwrap.dedent(body).strip() + "\n"))

PG = "import Database.PostgreSQL.Simple\nimport Data.String (fromString)"
# sql
add('sql','vulnerable','sql-1','C101',PG,"""
run :: Connection -> IO ()
run conn = do
  n <- getLine
  _ <- execute_ conn (fromString ("DELETE FROM t WHERE n = '" ++ n ++ "'"))
  pure ()""")
add('sql','vulnerable','sql-2','C102',PG,"""
find :: Connection -> IO [Only Int]
find conn = do
  col <- getLine
  query_ conn (fromString ("SELECT id FROM users ORDER BY " ++ col))""")
add('sql','vulnerable','sql-3','C103',PG+"\nimport System.Environment (getArgs)","""
main :: IO ()
main = do
  (who:_) <- getArgs
  conn <- connectPostgreSQL "dbname=app"
  _ <- query_ conn (fromString ("SELECT * FROM t WHERE owner = '" ++ who ++ "'")) :: IO [Only Int]
  pure ()""")
add('sql','safe','sql-1','C104',PG,"""
run :: Connection -> IO ()
run conn = do
  n <- getLine
  _ <- execute conn "DELETE FROM t WHERE n = ?" (Only n)
  pure ()""")
add('sql','safe','sql-2','C105',PG,"""
find :: Connection -> IO [Only Int]
find conn = query_ conn "SELECT id FROM users ORDER BY created_at\"""")
add('sql','safe','sql-3','C106',PG,"""
main :: IO ()
main = do
  who <- getLine
  conn <- connectPostgreSQL "dbname=app"
  _ <- query conn "SELECT * FROM t WHERE owner = ?" (Only who) :: IO [Only Int]
  pure ()""")
# cmd
PR = "import System.Process"
add('cmd','vulnerable','cmd-1','C201',PR,"""
run :: IO ()
run = do
  f <- getLine
  callCommand ("tar xf " ++ f)""")
add('cmd','vulnerable','cmd-2','C202',PR,"""
run :: IO ()
run = do
  h <- getLine
  _ <- readCreateProcess (shell ("ping -c1 " ++ h)) ""
  pure ()""")
add('cmd','vulnerable','cmd-3','C203',PR+"\nimport System.Environment (getArgs)","""
main :: IO ()
main = do
  (x:_) <- getArgs
  callCommand ("convert " ++ x ++ " out.png")""")
add('cmd','safe','cmd-1','C204',PR,"""
run :: IO ()
run = callProcess "tar" ["xf", "backup.tar"]""")
add('cmd','safe','cmd-2','C205',PR,"""
run :: IO ()
run = do
  _ <- readProcess "ls" ["-l", "/var/log"] ""
  pure ()""")
add('cmd','safe','cmd-3','C206',PR,"""
run :: IO ()
run = callCommand "date""" + '"')
# path
add('path','vulnerable','path-1','C301',"import System.IO","""
serve :: IO String
serve = do
  n <- getLine
  readFile ("/srv/files/" ++ n)""")
add('path','vulnerable','path-2','C302',"import System.Directory","""
drop' :: IO ()
drop' = do
  n <- getLine
  removeFile ("/tmp/up/" ++ n)""")
add('path','vulnerable','path-3','C303',"import System.Environment (getArgs)","""
main :: IO ()
main = do
  (p:_) <- getArgs
  writeFile p "x\"""")
add('path','safe','path-1','C304',"import System.IO","""
serve :: IO String
serve = readFile "/srv/files/index.html\"""")
add('path','safe','path-2','C305',"import System.Directory\nimport System.FilePath (takeFileName)","""
drop' :: IO ()
drop' = do
  n <- getLine
  removeFile ("/tmp/up/" ++ takeFileName n)""")
add('path','safe','path-3','C306',"import System.IO","""
main :: IO ()
main = writeFile "/var/log/app.out" "x\"""")
# ssrf
HC = "import Network.HTTP.Simple"
add('ssrf','vulnerable','ssrf-1','C401',HC,"""
fetch :: IO ()
fetch = do
  u <- getLine
  req <- parseRequest u
  _ <- httpLBS req
  pure ()""")
add('ssrf','vulnerable','ssrf-2','C402',HC,"""
fetch :: IO ()
fetch = do
  h <- getLine
  req <- parseRequest ("http://" ++ h ++ "/status")
  _ <- httpLBS req
  pure ()""")
add('ssrf','vulnerable','ssrf-3','C403',HC+"\nimport System.Environment (getArgs)","""
main :: IO ()
main = do
  (u:_) <- getArgs
  req <- parseRequest u
  _ <- httpNoBody req
  pure ()""")
add('ssrf','safe','ssrf-1','C404',HC,"""
fetch :: IO ()
fetch = do
  req <- parseRequest "https://api.example.com/status"
  _ <- httpLBS req
  pure ()""")
add('ssrf','safe','ssrf-2','C405',HC,"""
fetch :: IO ()
fetch = do
  n <- getLine
  req <- parseRequest "https://api.example.com/items"
  _ <- httpLBS (setRequestQueryString [("name", Just (fromStr n))] req)
  pure ()
  where fromStr = undefined""")
add('ssrf','safe','ssrf-3','C406',HC,"""
fetch :: IO ()
fetch = do
  req <- parseRequest "https://internal.example.com/health"
  _ <- httpNoBody req
  pure ()""")
# sensitive data exposure
add('exposure','vulnerable','exp-1','C501',"import System.IO","""
login :: IO ()
login = do
  password <- getLine
  putStrLn ("login attempt with password " ++ password)""")
add('exposure','vulnerable','exp-2','C502',"import System.IO\nimport System.Environment (lookupEnv)","""
main :: IO ()
main = do
  apiKey <- lookupEnv "API_KEY"
  hPutStrLn stderr ("using key " ++ show apiKey)""")
add('exposure','vulnerable','exp-3','C503',"import Debug.Trace","""
check :: String -> Bool
check token = trace ("token=" ++ token) (not (null token))""")
add('exposure','safe','exp-1','C504',"import System.IO","""
login :: IO ()
login = do
  _ <- getLine
  putStrLn "login attempt received\"""")
add('exposure','safe','exp-2','C505',"import System.IO","""
main :: IO ()
main = hPutStrLn stderr "starting service\"""")
add('exposure','safe','exp-3','C506',"import Debug.Trace","""
check :: Int -> Bool
check n = trace ("count=" ++ show n) (n > 0)""")
# crypto
add('crypto','vulnerable','cry-1','C601',"import System.Random","""
newToken :: IO Int
newToken = randomRIO (0, 999999)""")
add('crypto','vulnerable','cry-2','C602',"import Crypto.Hash\nimport qualified Data.ByteString.Char8 as B","""
digest :: B.ByteString -> Digest MD5
digest = hash""")
add('crypto','vulnerable','cry-3','C603',"import System.Random","""
sessionId :: IO String
sessionId = do
  g <- getStdGen
  pure (show (fst (random g :: (Int, StdGen))))""")
add('crypto','safe','cry-1','C604',"import Crypto.Random\nimport qualified Data.ByteString as B","""
newToken :: IO B.ByteString
newToken = getRandomBytes 32""")
add('crypto','safe','cry-2','C605',"import Crypto.Hash\nimport qualified Data.ByteString.Char8 as B","""
digest :: B.ByteString -> Digest SHA256
digest = hash""")
add('crypto','safe','cry-3','C606',"import System.Random","""
shuffleSeed :: IO Int
shuffleSeed = randomRIO (1, 6)""")

man = []
for c in cases:
    os.makedirs(os.path.dirname(c['file']), exist_ok=True)
    open(c['file'], 'w').write(c.pop('source'))
    man.append(c)
json.dump(dict(schema='haskell-core-families/1', note='author-seed cases prove the harness; the PRD requires 25 vulnerable + 25 safe independent cases per family', cases=man), open('manifest.json','w'), indent=1)
print(len(man), 'cases')
