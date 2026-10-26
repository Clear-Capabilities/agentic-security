// Haskell cases for the metamorphic + adversarial mutation gate (bench/mutation/runner.mjs).
//
// WHY A SEPARATE FILE. The gate had no Haskell coverage at all, so a Haskell-only regression (an import-resolution change, a
// sanitizer-identity change, a taint-summary change) could not move any verdict here. These cases exercise the Haskell taint
// engine (producer IR-TAINT) through the same public scan the other languages use, on BOTH dimensions:
//
//   sanitization  the finding fires in every case; the question is whether the engine labels the flow `sanitized`.
//                 Sanitizers are identity-keyed (module + name, scanner/src/language/haskell-models.js), so a same-named user
//                 function, a sanitizer of the wrong family and a discarded result must NOT count.
//   detection     the question is whether a finding fires at all, one pair per sink family the model registry carries:
//                 command (CWE-78 / CWE-88), SQL (CWE-89), path (CWE-22), SSRF (CWE-918), open redirect (CWE-601),
//                 code evaluation (CWE-94) and XSS (CWE-79).
//
// Every group is a baseline, semantics-preserving rewrites (verdict must HOLD: renames, qualified imports, helpers, where
// bindings, application style) and semantics-changing near-misses (verdict must FLIP: literal-only input, a parameter bound
// instead of concatenated, an own function that shadows a library name, a shadowed variable, a result that is dropped).
//
// Written from the Haskell language and the libraries' documented APIs, not from the detector or from any corpus entry.

const HS = 'Main.hs';
const TAINT = /^IR-TAINT$/;

const san = (id, klass, expectSanitized, why, code, extra = {}) =>
  ({ id, class: klass, dimension: 'sanitization', file: HS, parser: TAINT, expectSanitized, why, code, ...extra });
const det = (id, klass, expectDetected, why, code, extra = {}) =>
  ({ id, class: klass, dimension: 'detection', file: HS, parser: TAINT, expectDetected, why, code, ...extra });

const PATH = { cwe: /CWE-22/ };
const XSS = { cwe: /CWE-79/ };
const CMD = { cwe: /CWE-78/ };
const ARG = { cwe: /CWE-88/ };
const SQL = { cwe: /CWE-89/ };
const SSRF = { cwe: /CWE-918/ };
const REDIR = { cwe: /CWE-601/ };
const CODE = { cwe: /CWE-94/ };

export const HASKELL_CASES = [
  // ── sanitization: path (takeFileName drops every directory component) ─────────────────────────────────────────────────
  san('hs-san-path-baseline', 'baseline', true, 'takeFileName from System.FilePath drops every directory component before the read', `module Main where
import System.FilePath (takeFileName)

main :: IO ()
main = do
  name <- getLine
  body <- readFile (takeFileName name)
  putStr body
`, PATH),
  san('hs-san-path-rename', 'metamorphic', true, 'renaming the bindings changes nothing about the flow', `module Main where
import System.FilePath (takeFileName)

main :: IO ()
main = do
  requestedThing <- getLine
  cleanedThing <- return (takeFileName requestedThing)
  contents <- readFile cleanedThing
  putStr contents
`, PATH),
  san('hs-san-path-let-indirection', 'metamorphic', true, 'an extra let copy of the clean value does not unsanitize it', `module Main where
import System.FilePath (takeFileName)

main :: IO ()
main = do
  name <- getLine
  let first = takeFileName name
      second = first
  body <- readFile second
  putStr body
`, PATH),
  san('hs-san-path-dollar', 'metamorphic', true, 'application with ($) is the same program as application by juxtaposition', `module Main where
import System.FilePath (takeFileName)

main :: IO ()
main = do
  name <- getLine
  body <- readFile $ takeFileName name
  putStr body
`, PATH),
  san('hs-san-path-qualified-import', 'metamorphic', true, 'a qualified import resolves to the same function', `module Main where
import qualified System.FilePath as FP

main :: IO ()
main = do
  name <- getLine
  body <- readFile (FP.takeFileName name)
  putStr body
`, PATH),
  san('hs-san-path-where-helper', 'metamorphic', true, 'moving the clean-up into a where-bound helper is the same flow', `module Main where
import System.FilePath (takeFileName)

main :: IO ()
main = do
  name <- getLine
  body <- readFile (tidy name)
  putStr body
  where
    tidy = takeFileName
`, PATH),
  san('hs-san-path-sanitizer-removed', 'adversarial', false, 'no sanitizer: the flow is genuinely unsanitized', `module Main where

main :: IO ()
main = do
  name <- getLine
  body <- readFile name
  putStr body
`, PATH),
  san('hs-san-path-wrong-function', 'adversarial', false, 'takeExtension keeps the directory components; it neutralizes nothing about traversal', `module Main where
import System.FilePath (takeExtension)

main :: IO ()
main = do
  name <- getLine
  body <- readFile (name ++ takeExtension name)
  putStr body
`, PATH),
  san('hs-san-path-result-discarded', 'adversarial', false, 'the cleaned value is computed and dropped; the sink gets the raw input', `module Main where
import System.FilePath (takeFileName)

main :: IO ()
main = do
  name <- getLine
  let _unused = takeFileName name
  body <- readFile name
  putStr body
`, PATH),
  san('hs-san-path-own-function-same-name', 'adversarial', false, 'a function of the same NAME defined in this module is not the library sanitizer', `module Main where

takeFileName :: FilePath -> FilePath
takeFileName p = p

main :: IO ()
main = do
  name <- getLine
  body <- readFile (takeFileName name)
  putStr body
`, PATH),
  san('hs-san-path-wrong-family', 'adversarial', false, 'an HTML escaper does not neutralize path traversal', `module Main where
import Text.Blaze.Html (toHtml)

main :: IO ()
main = do
  name <- getLine
  body <- readFile (show (toHtml name))
  putStr body
`, PATH),

  san('hs-san-path-toplevel-alias', 'metamorphic', true, 'a point-free top-level alias of the sanitizer IS the sanitizer', `module Main where
import System.FilePath (takeFileName)

tidy :: FilePath -> FilePath
tidy = takeFileName

main :: IO ()
main = do
  name <- getLine
  body <- readFile (tidy name)
  putStr body
`, PATH),
  san('hs-san-path-composed-alias', 'metamorphic', true, 'an alias that composes the sanitizer with id still ends in the sanitizer', `module Main where
import System.FilePath (takeFileName)

tidy :: FilePath -> FilePath
tidy = id . takeFileName

main :: IO ()
main = do
  name <- getLine
  body <- readFile (tidy name)
  putStr body
`, PATH),
  san('hs-san-path-alias-of-identity', 'adversarial', false, 'an alias of id passes the value through untouched', `module Main where

tidy :: FilePath -> FilePath
tidy = id

main :: IO ()
main = do
  name <- getLine
  body <- readFile (tidy name)
  putStr body
`, PATH),
  san('hs-san-path-alias-of-wrong-function', 'adversarial', false, 'an alias of a function that is not a sanitizer does not become one', `module Main where
import System.FilePath (takeExtension)

tidy :: FilePath -> String
tidy = takeExtension

main :: IO ()
main = do
  name <- getLine
  body <- readFile (name ++ tidy name)
  putStr body
`, PATH),

  // ── sanitization: XSS (toHtml escapes, preEscapedToHtml trusts) ──────────────────────────────────────────────────────
  san('hs-san-xss-baseline', 'baseline', true, 'toHtml escapes the text before it reaches the pre-escaped sink', `module Main where
import Text.Blaze.Html (toHtml, preEscapedToHtml)
import Text.Blaze.Html.Renderer.String (renderHtml)

main :: IO ()
main = do
  name <- getLine
  putStrLn (renderHtml (preEscapedToHtml (renderHtml (toHtml name))))
`, XSS),
  san('hs-san-xss-let-rename', 'metamorphic', true, 'a renamed let binding of the escaped value is the same flow', `module Main where
import Text.Blaze.Html (toHtml, preEscapedToHtml)
import Text.Blaze.Html.Renderer.String (renderHtml)

main :: IO ()
main = do
  visitorSuppliedText <- getLine
  let escapedForPage = renderHtml (toHtml visitorSuppliedText)
  putStrLn (renderHtml (preEscapedToHtml escapedForPage))
`, XSS),
  san('hs-san-xss-no-escape', 'adversarial', false, 'no escaping before the pre-escaped sink', `module Main where
import Text.Blaze.Html (preEscapedToHtml)
import Text.Blaze.Html.Renderer.String (renderHtml)

main :: IO ()
main = do
  name <- getLine
  putStrLn (renderHtml (preEscapedToHtml name))
`, XSS),
  san('hs-san-xss-wrong-family', 'adversarial', false, 'takeFileName neutralizes traversal, not markup', `module Main where
import System.FilePath (takeFileName)
import Text.Blaze.Html (preEscapedToHtml)
import Text.Blaze.Html.Renderer.String (renderHtml)

main :: IO ()
main = do
  name <- getLine
  putStrLn (renderHtml (preEscapedToHtml (takeFileName name)))
`, XSS),

  // ── detection: command injection through a shell string (CWE-78) ────────────────────────────────────────────────────
  det('hs-det-cmd-baseline', 'baseline', true, 'standard input concatenated into a shell string is command injection', `module Main where
import System.Process (callCommand)

main :: IO ()
main = do
  host <- getLine
  callCommand ("ping -c1 " ++ host)
`, CMD),
  det('hs-det-cmd-rename', 'metamorphic', true, 'renaming the binding changes nothing', `module Main where
import System.Process (callCommand)

main :: IO ()
main = do
  somethingTheUserTyped <- getLine
  callCommand ("ping -c1 " ++ somethingTheUserTyped)
`, CMD),
  det('hs-det-cmd-qualified-import', 'metamorphic', true, 'a qualified import resolves to the same function', `module Main where
import qualified System.Process as P

main :: IO ()
main = do
  host <- getLine
  P.callCommand ("ping -c1 " ++ host)
`, CMD),
  det('hs-det-cmd-bind-chain', 'metamorphic', true, 'monadic bind instead of a do-binding is the same flow', `module Main where
import System.Process (callCommand)

main :: IO ()
main = getLine >>= \\host -> callCommand ("ping -c1 " ++ host)
`, CMD),
  det('hs-det-cmd-helper-function', 'metamorphic', true, 'hoisting the sink into a same-module helper keeps the flow', `module Main where
import System.Process (callCommand)

probe :: String -> IO ()
probe target = callCommand ("ping -c1 " ++ target)

main :: IO ()
main = do
  host <- getLine
  probe host
`, CMD),
  det('hs-det-cmd-returning-helper', 'metamorphic', true, 'a helper that returns the tainted value carries it to the sink', `module Main where
import System.Process (callCommand)

build :: String -> String
build h = "ping -c1 " ++ h

main :: IO ()
main = do
  host <- getLine
  callCommand (build host)
`, CMD),
  det('hs-det-cmd-environment-source', 'metamorphic', true, 'an environment variable is another untrusted source for the same sink', `module Main where
import System.Environment (getEnv)
import System.Process (callCommand)

main :: IO ()
main = do
  host <- getEnv "TARGET_HOST"
  callCommand ("ping -c1 " ++ host)
`, CMD),
  det('hs-det-cmd-alias-of-sink', 'metamorphic', true, 'a point-free alias of the sink IS the sink', `module Main where
import System.Process (callCommand)

run :: String -> IO ()
run = callCommand

main :: IO ()
main = do
  host <- getLine
  run ("ping -c1 " ++ host)
`, CMD),
  det('hs-det-cmd-alias-of-sink-literal', 'adversarial', false, 'the same alias given a constant carries no input', `module Main where
import System.Process (callCommand)

run :: String -> IO ()
run = callCommand

main :: IO ()
main = do
  _ <- getLine
  run "ping -c1 127.0.0.1"
`, CMD),
  det('hs-det-cmd-literal-only', 'adversarial', false, 'a constant command line carries no input', `module Main where
import System.Process (callCommand)

main :: IO ()
main = do
  _ <- getLine
  callCommand "ping -c1 127.0.0.1"
`, CMD),
  det('hs-det-cmd-length-only', 'adversarial', false, 'length returns a number; no caller text survives into the command', `module Main where
import System.Process (callCommand)

main :: IO ()
main = do
  host <- getLine
  callCommand ("sleep " ++ show (length host))
`, CMD),
  det('hs-det-cmd-own-function-same-name', 'adversarial', false, 'a callCommand defined in this module is not System.Process.callCommand', `module Main where

callCommand :: String -> IO ()
callCommand s = putStrLn ("would run: " ++ s)

main :: IO ()
main = do
  host <- getLine
  callCommand ("ping -c1 " ++ host)
`, CMD),
  det('hs-det-cmd-variable-shadowed', 'adversarial', false, 'a let that rebinds the name to a constant means the sink sees the constant', `module Main where
import System.Process (callCommand)

main :: IO ()
main = do
  host <- getLine
  let host = "127.0.0.1"
  callCommand ("ping -c1 " ++ host)
`, CMD),

  // ── detection: argument injection through an argv list (CWE-88) ─────────────────────────────────────────────────────
  det('hs-det-argv-baseline', 'baseline', true, 'input placed in the argument vector lets the caller steer the program (option injection)', `module Main where
import System.Process (callProcess)

main :: IO ()
main = do
  archive <- getLine
  callProcess "tar" ["xf", archive]
`, ARG),
  det('hs-det-argv-renamed', 'metamorphic', true, 'renaming the binding changes nothing', `module Main where
import System.Process (callProcess)

main :: IO ()
main = do
  whatWasTyped <- getLine
  callProcess "tar" ["xf", whatWasTyped]
`, ARG),
  det('hs-det-argv-literal-arguments', 'adversarial', false, 'every argument is a constant', `module Main where
import System.Process (callProcess)

main :: IO ()
main = do
  _ <- getLine
  callProcess "tar" ["xf", "backup.tar"]
`, ARG),

  // ── detection: SQL (CWE-89), the query TEXT is the sink, bound parameters are the safe form ──────────────────────────
  det('hs-det-sql-baseline', 'baseline', true, 'input concatenated into the query text is SQL injection', `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Data.String (fromString)
import Database.PostgreSQL.Simple

main :: IO ()
main = do
  conn <- connectPostgreSQL "dbname=shop"
  ref <- getLine
  rows <- query_ conn (fromString ("SELECT status FROM orders WHERE ref = '" ++ ref ++ "'")) :: IO [Only String]
  print rows
`, SQL),
  det('hs-det-sql-renamed-and-let', 'metamorphic', true, 'building the text in a let under other names is the same flow', `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Data.String (fromString)
import Database.PostgreSQL.Simple

main :: IO ()
main = do
  handle <- connectPostgreSQL "dbname=shop"
  typed <- getLine
  let statement = "SELECT status FROM orders WHERE ref = '" ++ typed ++ "'"
  rows <- query_ handle (fromString statement) :: IO [Only String]
  print rows
`, SQL),
  det('hs-det-sql-sqlite-backend', 'metamorphic', true, 'another driver with the same query-text sink is the same defect', `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Data.String (fromString)
import Database.SQLite.Simple

main :: IO ()
main = do
  conn <- open "shop.db"
  ref <- getLine
  rows <- query_ conn (fromString ("SELECT status FROM orders WHERE ref = '" ++ ref ++ "'")) :: IO [Only String]
  print rows
`, SQL),
  det('hs-det-sql-bound-parameter', 'adversarial', false, 'the value is bound through Only; the query text is a constant', `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Database.PostgreSQL.Simple

main :: IO ()
main = do
  conn <- connectPostgreSQL "dbname=shop"
  ref <- getLine
  rows <- query conn "SELECT status FROM orders WHERE ref = ?" (Only (ref :: String)) :: IO [Only String]
  print rows
`, SQL),
  det('hs-det-sql-bound-parameter-sqlite', 'adversarial', false, 'the same parameter binding with the other driver', `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Database.SQLite.Simple

main :: IO ()
main = do
  conn <- open "shop.db"
  ref <- getLine
  rows <- query conn "SELECT status FROM orders WHERE ref = ?" (Only (ref :: String)) :: IO [Only String]
  print rows
`, SQL),

  // ── detection: path traversal (CWE-22) ───────────────────────────────────────────────────────────────────────────────
  det('hs-det-path-baseline', 'baseline', true, 'a command-line argument used as the file to read is path traversal', `module Main where
import System.Environment (getArgs)

main :: IO ()
main = do
  args <- getArgs
  body <- readFile (head args)
  putStr body
`, PATH),
  det('hs-det-path-prefix-concat', 'metamorphic', true, 'a fixed directory prefix does not stop a ../ in the rest', `module Main where

main :: IO ()
main = do
  name <- getLine
  body <- readFile ("/srv/data/" ++ name)
  putStr body
`, PATH),
  det('hs-det-path-write', 'metamorphic', true, 'writeFile is a path sink as well as readFile', `module Main where

main :: IO ()
main = do
  name <- getLine
  writeFile ("/srv/data/" ++ name) "x"
`, PATH),
  det('hs-det-path-literal-only', 'adversarial', false, 'a constant path carries no input', `module Main where

main :: IO ()
main = do
  _ <- getLine
  body <- readFile "/srv/data/report.txt"
  putStr body
`, PATH),
  det('hs-det-path-length-only', 'adversarial', false, 'only the length of the input reaches the path', `module Main where

main :: IO ()
main = do
  name <- getLine
  body <- readFile ("/srv/data/part" ++ show (length name))
  putStr body
`, PATH),

  // ── detection: server-side request forgery (CWE-918) ─────────────────────────────────────────────────────────────────
  det('hs-det-ssrf-baseline', 'baseline', true, 'a URL taken from input and turned into a request is SSRF', `module Main where
import Network.HTTP.Client

main :: IO ()
main = do
  target <- getLine
  req <- parseRequest target
  manager <- newManager defaultManagerSettings
  _ <- httpLbs req manager
  return ()
`, SSRF),
  det('hs-det-ssrf-renamed-qualified', 'metamorphic', true, 'a qualified import under another name and a renamed binding are the same program', `module Main where
import qualified Network.HTTP.Client as C

main :: IO ()
main = do
  whereToGo <- getLine
  r <- C.parseRequest whereToGo
  m <- C.newManager C.defaultManagerSettings
  _ <- C.httpLbs r m
  return ()
`, SSRF),
  det('hs-det-ssrf-literal-url', 'adversarial', false, 'a constant URL is not attacker-steerable', `module Main where
import Network.HTTP.Client

main :: IO ()
main = do
  _ <- getLine
  req <- parseRequest "https://api.example.com/status"
  manager <- newManager defaultManagerSettings
  _ <- httpLbs req manager
  return ()
`, SSRF),

  // ── detection: open redirect (CWE-601) ───────────────────────────────────────────────────────────────────────────────
  det('hs-det-redirect-baseline', 'baseline', true, 'redirecting to a request-supplied location is an open redirect', `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Web.Scotty
import qualified Data.Text.Lazy as TL

main :: IO ()
main = scotty 3000 $
  get "/go" $ do
    next <- queryParam "next"
    redirect (next :: TL.Text)
`, REDIR),
  det('hs-det-redirect-renamed', 'metamorphic', true, 'renaming the binding changes nothing', `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Web.Scotty
import qualified Data.Text.Lazy as TL

main :: IO ()
main = scotty 3000 $
  get "/go" $ do
    wherever <- queryParam "to"
    redirect (wherever :: TL.Text)
`, REDIR),
  det('hs-det-redirect-fixed-target', 'adversarial', false, 'a constant location cannot be steered', `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Web.Scotty

main :: IO ()
main = scotty 3000 $
  get "/go" $ do
    _ <- queryParam "next" :: ActionM String
    redirect "/home"
`, REDIR),

  // ── detection: code evaluation (CWE-94) ──────────────────────────────────────────────────────────────────────────────
  det('hs-det-code-baseline', 'baseline', true, 'evaluating Haskell source from the command line runs attacker code', `module Main where
import Language.Haskell.Interpreter
import System.Environment (getArgs)

main :: IO ()
main = do
  args <- getArgs
  r <- runInterpreter (setImports ["Prelude"] >> interpret (head args) (as :: Int))
  print r
`, CODE),
  det('hs-det-code-literal-source', 'adversarial', false, 'evaluating a constant expression runs nothing the author did not write', `module Main where
import Language.Haskell.Interpreter

main :: IO ()
main = do
  _ <- getLine
  r <- runInterpreter (setImports ["Prelude"] >> interpret "1 + 2" (as :: Int))
  print r
`, CODE),

  // ── detection: XSS (CWE-79), the pre-escaped constructor is the sink ─────────────────────────────────────────────────
  det('hs-det-xss-baseline', 'baseline', true, 'input handed to the pre-escaped constructor is rendered as markup', `module Main where
import Text.Blaze.Html (preEscapedToHtml)
import Text.Blaze.Html.Renderer.String (renderHtml)

main :: IO ()
main = do
  comment <- getLine
  putStrLn (renderHtml (preEscapedToHtml comment))
`, XSS),
  det('hs-det-xss-renamed', 'metamorphic', true, 'renaming the binding changes nothing', `module Main where
import Text.Blaze.Html (preEscapedToHtml)
import Text.Blaze.Html.Renderer.String (renderHtml)

main :: IO ()
main = do
  whatTheVisitorSaid <- getLine
  putStrLn (renderHtml (preEscapedToHtml whatTheVisitorSaid))
`, XSS),
  det('hs-det-xss-escaping-constructor', 'adversarial', false, 'toHtml escapes; it is not a sink', `module Main where
import Text.Blaze.Html (toHtml)
import Text.Blaze.Html.Renderer.String (renderHtml)

main :: IO ()
main = do
  comment <- getLine
  putStrLn (renderHtml (toHtml comment))
`, XSS),
];
