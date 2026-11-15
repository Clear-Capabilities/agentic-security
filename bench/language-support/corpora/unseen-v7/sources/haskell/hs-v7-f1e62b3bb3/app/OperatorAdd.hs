module Main (main) where

import Crypto.Hash.MD5 (hash)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BC
import Database.SQLite.Simple
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO

main :: IO ()
main = do
  args <- getArgs
  case args of
    [login] -> addOperator login
    _ -> hPutStrLn stderr "usage: operator-add <login>" >> exitFailure

addOperator :: String -> IO ()
addOperator login = do
  putStr "Password: " >> hFlush stdout
  hSetEcho stdin False
  pw <- BC.getLine
  hSetEcho stdin True
  putStrLn ""
  conn <- open "operators.db"
  execute conn "INSERT INTO operators (login, password_hash) VALUES (?, ?)" (login, digest pw)
  close conn
  putStrLn ("operator " ++ login ++ " created")

digest :: BC.ByteString -> BC.ByteString
digest = B16.encode . hash
