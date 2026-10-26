{-# LANGUAGE OverloadedStrings #-}
module Preview (fetchPreview) where

import Network.HTTP.Simple
import Network.URI (parseURI, uriAuthority, uriRegName)
import Web.Scotty
import qualified Data.Text.Lazy as TL

allowedHosts :: [String]
allowedHosts = ["example.org", "images.example.org"]

fetchPreview :: ActionM ()
fetchPreview = do
  url <- param "url"
  case parseURI (TL.unpack url) >>= uriAuthority of
    Just auth | uriRegName auth `elem` allowedHosts -> do
      req <- liftAndCatchIO (parseRequest (TL.unpack url))
      resp <- liftAndCatchIO (httpLBS req)
      text (TL.pack (show (getResponseStatusCode resp)))
    _ -> status badRequest400 >> text "host not allowed"
