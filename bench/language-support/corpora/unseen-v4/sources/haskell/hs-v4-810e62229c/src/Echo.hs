module Echo (serve) where

import Network.Socket
import Network.Socket.ByteString (recv, sendAll)
import qualified Data.ByteString as BS
import Control.Monad (forever)

serve :: Socket -> IO ()
serve sock = forever $ do
  (conn, _) <- accept sock
  msg <- recvAll conn BS.empty
  sendAll conn msg
  close conn
  where
    recvAll c acc = do
      chunk <- recv c 4096
      if BS.null chunk then pure acc else recvAll c (acc <> chunk)
