{-# LANGUAGE OverloadedStrings #-}
module WebhookPreview (previewRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Lazy as TL
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Web.Scotty

previewRoutes :: ScottyM ()
previewRoutes = do
  manager <- liftIO (newManager tlsManagerSettings)
  post "/webhooks/preview" $ do
    target <- param "url"
    request <- liftIO (parseRequest (TL.unpack target))
    response <- liftIO (httpLbs request { method = "GET" } manager)
    let shown = BL.take 2048 (responseBody response)
    setHeader "Content-Type" "text/plain"
    raw shown
