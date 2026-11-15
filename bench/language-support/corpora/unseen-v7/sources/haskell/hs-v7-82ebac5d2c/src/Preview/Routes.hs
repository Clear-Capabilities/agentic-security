{-# LANGUAGE OverloadedStrings #-}
module Preview.Routes (previewRoutes) where

import Control.Lens ((^.))
import Control.Monad.IO.Class (liftIO)
import qualified Data.Set as Set
import qualified Data.Text.Lazy as TL
import Network.HTTP.Types.Status (status400)
import Network.URI (URI(..), URIAuth(..), parseURI)
import Network.Wreq (get, responseBody)
import Web.Scotty

allowedHosts :: Set.Set String
allowedHosts = Set.fromList ["cdn.ticketing.example", "images.ticketing.example"]

permitted :: String -> Maybe URI
permitted raw = do
  uri <- parseURI raw
  auth <- uriAuthority uri
  if uriScheme uri == "https:" && Set.member (uriRegName auth) allowedHosts
    then Just uri
    else Nothing

previewRoutes :: ScottyM ()
previewRoutes =
  get "/preview" $ do
    target <- param "url"
    case permitted (TL.unpack target) of
      Nothing -> status status400 >> text "preview host not permitted"
      Just uri -> do
        r <- liftIO (get (show uri))
        setHeader "Content-Type" "image/png"
        raw (r ^. responseBody)
