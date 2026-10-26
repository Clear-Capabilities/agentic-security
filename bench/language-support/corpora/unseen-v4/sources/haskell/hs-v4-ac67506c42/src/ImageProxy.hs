module ImageProxy (proxyImage) where

import Network.Wreq (get, responseBody)
import Control.Lens ((^.))
import Network.Wai
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map as M

images :: M.Map B.ByteString String
images = M.fromList
  [ (B.pack "logo", "https://cdn.example.org/logo.png")
  , (B.pack "banner", "https://cdn.example.org/banner.png") ]

-- The query parameter only selects an entry from a fixed table of URLs.
proxyImage :: Request -> IO BL.ByteString
proxyImage req = do
  let target = case lookup (B.pack "src") (queryString req) of
        Just (Just k) | Just u <- M.lookup k images -> u
        _ -> "https://cdn.example.org/placeholder.png"
  r <- get target
  pure (r ^. responseBody)
