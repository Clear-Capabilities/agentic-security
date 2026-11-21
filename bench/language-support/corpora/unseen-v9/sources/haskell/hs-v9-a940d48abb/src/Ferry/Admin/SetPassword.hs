module Ferry.Admin.SetPassword (main) where

import qualified Crypto.Hash.SHA1 as SHA1
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BC
import System.Environment (getArgs)
import System.IO (hSetEcho, hGetLine, stdin)

operatorsFile :: FilePath
operatorsFile = "/etc/ferry/operators"

main :: IO ()
main = do
  args <- getArgs
  case args of
    [username] -> do
      hSetEcho stdin False
      secret <- hGetLine stdin
      hSetEcho stdin True
      let digest = SHA1.hash (BC.pack secret)
      BC.appendFile operatorsFile (BC.pack username <> ":" <> B16.encode digest <> "\n")
    _ -> putStrLn "usage: ferry-set-password <username>"
