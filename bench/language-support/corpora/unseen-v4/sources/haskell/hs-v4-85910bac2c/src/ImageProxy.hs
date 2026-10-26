module ImageProxy (proxyImage) where

import Network.Wreq (get, responseBody)
import Control.Lens ((^.))
import Network.Wai
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as BL

proxyImage :: Request -> IO BL.ByteString
proxyImage req = do
  let target = case lookup (B.pack "src") (queryString req) of
        Just (Just u) -> B.unpack u
        _             -> "http://localhost/placeholder.png"
  r <- get target
  pure (r ^. responseBody)
