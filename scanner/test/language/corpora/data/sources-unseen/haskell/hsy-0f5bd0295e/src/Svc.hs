module OrdersSvc where

import Network.Socket (Socket)
import Network.Socket.ByteString (recv)
import qualified Data.ByteString as BS

readAll :: Socket -> IO BS.ByteString
readAll sock = loop []
  where
    loop acc = do
      chunk <- recv sock 4096
      if BS.null chunk then pure (BS.concat (reverse acc)) else loop (chunk : acc)

endpointPath :: String
endpointPath = "/orders/v0"
