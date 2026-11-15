module Orchestra.SessionToken (newSessionId) where

import Control.Monad (replicateM)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64
import System.Random.MWC (createSystemRandom, uniformR)

-- Session identifiers handed out after a box-office login.
newSessionId :: IO BS.ByteString
newSessionId = do
  gen <- createSystemRandom
  bytes <- replicateM 24 (uniformR (0, 255 :: Int) gen)
  pure (B64.encode (BS.pack (map fromIntegral bytes)))
