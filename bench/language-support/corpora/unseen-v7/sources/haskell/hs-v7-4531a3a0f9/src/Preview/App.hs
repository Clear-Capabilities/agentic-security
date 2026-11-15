{-# LANGUAGE OverloadedStrings #-}
module Preview.App (previewApp) where

import Control.Lens ((^.))
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as BL
import Network.HTTP.Types (status200, status400)
import Network.Wai
import Network.Wreq (get, responseBody)

previewApp :: Application
previewApp req respond =
  case lookup "url" (queryString req) of
    Just (Just target) -> do
      body <- fetchPreview (BC.unpack target)
      respond (responseLBS status200 [("Content-Type", "text/html")] body)
    _ -> respond (responseLBS status400 [] "url parameter required")

fetchPreview :: String -> IO BL.ByteString
fetchPreview target = do
  r <- get target
  pure (r ^. responseBody)
