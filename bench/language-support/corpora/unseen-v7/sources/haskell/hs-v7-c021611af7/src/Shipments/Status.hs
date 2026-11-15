{-# LANGUAGE OverloadedStrings #-}
module Shipments.Status (statusApp) where

import Control.Monad (join)
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Network.HTTP.Types (status200)
import Network.Wai

escapeHtml :: Text -> Text
escapeHtml = T.concatMap esc
  where
    esc '<'  = "&lt;"
    esc '>'  = "&gt;"
    esc '&'  = "&amp;"
    esc '"'  = "&quot;"
    esc '\'' = "&#39;"
    esc c    = T.singleton c

statusApp :: Application
statusApp req respond = do
  let code = maybe "" TE.decodeUtf8 (join (lookup "code" (queryString req)))
      page = T.concat
        [ "<!doctype html><html><body>"
        , "<h1>Shipment ", escapeHtml code, "</h1>"
        , "<p>Status lookups are refreshed every ten minutes.</p>"
        , "</body></html>"
        ]
  respond (responseLBS status200 [("Content-Type", "text/html; charset=utf-8")] (BL.fromStrict (TE.encodeUtf8 page)))
