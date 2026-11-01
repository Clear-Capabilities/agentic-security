module AdminUsers (main) where

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString.Base16 as B16
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
    _ -> putStrLn "usage: admin-users USER PASSWORD" >> exitFailure

verifyLogin :: B.ByteString -> B.ByteString -> Bool
verifyLogin stored supplied = stored == B16.encode (SHA256.hash supplied)
