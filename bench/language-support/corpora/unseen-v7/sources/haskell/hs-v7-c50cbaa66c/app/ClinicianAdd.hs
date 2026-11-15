module Main (main) where

import Crypto.PasswordStore (makePassword)
import qualified Data.ByteString.Char8 as BC
import Database.SQLite.Simple
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO

main :: IO ()
main = do
  args <- getArgs
  case args of
    [login, ward] -> addClinician login ward
    _ -> hPutStrLn stderr "usage: clinician-add <login> <ward>" >> exitFailure

readPassword :: IO BC.ByteString
readPassword = do
  putStr "Password: " >> hFlush stdout
  hSetEcho stdin False
  pw <- BC.getLine
  hSetEcho stdin True
  putStrLn ""
  pure pw

addClinician :: String -> String -> IO ()
addClinician login ward = do
  pw <- readPassword
  stored <- makePassword pw 17
  conn <- open "clinicians.db"
  execute conn "INSERT INTO clinicians (login, ward, password_hash) VALUES (?, ?, ?)" (login, ward, stored)
  close conn
  putStrLn ("clinician " ++ login ++ " added to " ++ ward)
