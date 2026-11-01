{-# LANGUAGE OverloadedStrings #-}
module LinkPreview (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Lazy as TL
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Web.Scotty

main :: IO ()
main = do
  manager <- newManager tlsManagerSettings
  scotty 8080 $
    get "/preview" $ do
      url <- param "url"
      request <- liftIO (parseRequest (TL.unpack url))
      response <- liftIO (httpLbs request manager)
      let body = responseBody response
      json (TL.pack (show (BL.length body)), TL.take 120 (TL.pack (show (BL.take 512 body))))
