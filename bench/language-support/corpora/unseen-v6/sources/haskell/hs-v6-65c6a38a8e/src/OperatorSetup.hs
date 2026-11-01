module OperatorSetup (main) where

import Crypto.Scrypt (EncryptedPass(..), Pass(..), defaultParams, encryptPassIO)
import qualified Data.ByteString.Char8 as B
import Database.SQLite.Simple
import System.IO

main :: IO ()
main = do
  putStr "operator name: " >> hFlush stdout
  name <- getLine
  putStr "password: " >> hFlush stdout
  hSetEcho stdin False
  password <- getLine
  hSetEcho stdin True
  putStrLn ""
  conn <- open "/var/lib/console/operators.db"
  stored <- storeOperator conn name password
  putStrLn ("stored operator " ++ name ++ " (" ++ show (B.length stored) ++ " byte hash)")
  close conn

storeOperator :: Connection -> String -> String -> IO B.ByteString
storeOperator conn name password = do
  EncryptedPass digest <- encryptPassIO defaultParams (Pass (B.pack password))
  execute conn "INSERT INTO operators (name, password_hash) VALUES (?, ?)" (name, digest)
  pure digest
