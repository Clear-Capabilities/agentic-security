module Ferry.Admin.Operators (main) where

import Crypto.KDF.PBKDF2 (fastPBKDF2_SHA256, Parameters(..))
import Crypto.Random (getRandomBytes)
import qualified Data.ByteString as BS
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
      salt <- getRandomBytes 16 :: IO BS.ByteString
      let digest = fastPBKDF2_SHA256 (Parameters 310000 32) (BC.pack secret) salt :: BS.ByteString
      BC.appendFile operatorsFile (BC.pack username <> ":" <> B16.encode salt <> ":" <> B16.encode digest <> "\n")
    _ -> putStrLn "usage: ferry-set-password <username>"
