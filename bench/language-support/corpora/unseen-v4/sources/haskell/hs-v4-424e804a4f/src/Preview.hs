{-# LANGUAGE OverloadedStrings #-}
module Preview (fetchPreview) where

import Network.HTTP.Simple
import Web.Scotty
import qualified Data.Text.Lazy as TL

fetchPreview :: ActionM ()
fetchPreview = do
  url <- param "url"
  req <- liftAndCatchIO (parseRequest (TL.unpack url))
  resp <- liftAndCatchIO (httpLBS req)
  text (TL.pack (show (getResponseStatusCode resp)))
