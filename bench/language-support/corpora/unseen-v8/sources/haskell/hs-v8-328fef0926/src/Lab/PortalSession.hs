module Lab.PortalSession (Session (..), mintSession) where

import Crypto.Random (getRandomBytes)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64
import Data.Time (UTCTime, getCurrentTime)

data Session = Session { sessionId :: BS.ByteString, analyst :: String, startedAt :: UTCTime }

mintSession :: String -> IO Session
mintSession analystLogin = do
  raw <- getRandomBytes 32 :: IO BS.ByteString
  now <- getCurrentTime
  pure (Session (B64.encode raw) analystLogin now)
