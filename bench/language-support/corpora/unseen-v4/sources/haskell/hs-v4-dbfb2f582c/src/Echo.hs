module Echo (serve) where

import Network.Socket
import Network.Socket.ByteString (recv, sendAll)
import qualified Data.ByteString as BS
import Control.Monad (forever)

maxMessage :: Int
maxMessage = 1048576

serve :: Socket -> IO ()
serve sock = forever $ do
  (conn, _) <- accept sock
  msg <- recvUpTo conn BS.empty
  sendAll conn msg
  close conn
  where
    recvUpTo c acc
      | BS.length acc >= maxMessage = pure (BS.take maxMessage acc)
      | otherwise = do
          chunk <- recv c 4096
          if BS.null chunk then pure acc else recvUpTo c (acc <> chunk)
