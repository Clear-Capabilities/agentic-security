module AccountTool (main) where

import Crypto.Scrypt (EncryptedPass (..), Pass (..), verifyPass')
import qualified Data.ByteString.Char8 as B
import Database.SQLite.Simple
import System.Environment (getArgs)
import System.Exit (exitFailure, exitSuccess)

main :: IO ()
main = do
  args <- getArgs
  case args of
    [user, supplied] -> do
      conn <- open "admin.db"
      rows <- query conn "SELECT password_digest FROM admins WHERE username = ?" (Only user) :: IO [Only B.ByteString]
      close conn
      case rows of
        (Only stored : _) | verifyLogin stored (B.pack supplied) -> putStrLn "ok" >> exitSuccess
        _ -> putStrLn "denied" >> exitFailure
    _ -> putStrLn "usage: account-tool USER PASSWORD" >> exitFailure

verifyLogin :: B.ByteString -> B.ByteString -> Bool
verifyLogin stored supplied = verifyPass' (Pass supplied) (EncryptedPass stored)
