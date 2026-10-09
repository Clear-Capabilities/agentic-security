module UsersSvc where

import Network.Socket (Socket)
import Network.Socket.ByteString (recv)
import qualified Data.ByteString as BS

readCapped :: Socket -> IO BS.ByteString
readCapped sock = loop 0 []
  where
    limit = 65536 :: Int
    loop total acc
      | total >= limit = pure (BS.concat (reverse acc))
      | otherwise = do
          chunk <- recv sock 4096
          if BS.null chunk then pure (BS.concat (reverse acc)) else loop (total + BS.length chunk) (chunk : acc)

endpointPath :: String
endpointPath = "/users/v0"
