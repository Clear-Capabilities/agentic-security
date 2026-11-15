{-# LANGUAGE OverloadedStrings #-}
module Fleet.DriverProfile (driverRoutes) where

import Data.Text (Text)
import Text.Blaze.Html.Renderer.Text (renderHtml)
import Text.Blaze.Html5 (Html, (!))
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A
import Web.Scotty

data Driver = Driver { driverName :: Text, depot :: Text, licenceClass :: Text }

profile :: Driver -> Html
profile d = H.docTypeHtml $ do
  H.head (H.title "Driver profile")
  H.body $ do
    H.h1 (H.toHtml (driverName d))
    H.dl $ do
      H.dt "Depot" >> H.dd (H.toHtml (depot d))
      H.dt "Licence" >> H.dd (H.toHtml (licenceClass d))
    H.a ! A.href "/drivers" $ "Back to roster"

driverRoutes :: ScottyM ()
driverRoutes =
  post "/drivers/preview" $ do
    d <- Driver <$> param "name" <*> param "depot" <*> param "licence"
    html (renderHtml (profile d))
