{-# LANGUAGE DataKinds, OverloadedStrings, TypeOperators #-}
module ProfileCard (app) where

import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Lucid
import Servant
import Servant.HTML.Lucid (HTML)

type API = "profiles" :> Capture "handle" Text :> "card" :> QueryParam "tagline" Text :> Get '[HTML] (Html ())

card :: Text -> Maybe Text -> Html ()
card handle tagline = html_ $ body_ $
  div_ [class_ "card"] $ do
    h2_ (toHtml ("@" <> handle))
    p_ [class_ "tagline"] (toHtml (fromMaybe "No tagline yet" tagline))
    a_ [href_ "/profiles"] "All profiles"

cardHandler :: Text -> Maybe Text -> Handler (Html ())
cardHandler handle tagline = pure (card handle tagline)

app :: Application
app = serve (Proxy :: Proxy API) cardHandler
