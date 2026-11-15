{-# LANGUAGE OverloadedStrings #-}
module Lab.SampleLabel (labelApp) where

import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Text.Encoding.Error (lenientDecode)
import Lucid
import Network.HTTP.Types (status200, status404)
import Network.Wai

labelPage :: Text -> Text -> Html ()
labelPage barcode description = doctypehtml_ $ do
  head_ (title_ "Sample label")
  body_ $ do
    h1_ (toHtml barcode)
    p_ [class_ "description"] (toHtml description)

labelApp :: Application
labelApp req respond =
  case (pathInfo req, lookup "description" (queryString req)) of
    (["samples", barcode, "label"], Just (Just d)) ->
      respond (responseLBS status200 [("Content-Type", "text/html; charset=utf-8")]
                 (renderBS (labelPage barcode (TE.decodeUtf8With lenientDecode d))))
    _ -> respond (responseLBS status404 [] "no such label")
