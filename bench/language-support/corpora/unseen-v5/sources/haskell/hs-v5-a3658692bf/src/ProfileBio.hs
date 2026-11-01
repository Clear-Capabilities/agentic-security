{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module ProfileBio (BioApi, bioServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import Servant
import Servant.HTML.Blaze (HTML)
import Text.Blaze.Html5 ((!), Html, preEscapedToHtml, toHtml)
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A

data Profile = Profile { handle :: Text, bio :: Text }

instance FromRow Profile where
  fromRow = Profile <$> field <*> field

type BioApi = "members" :> Capture "handle" Text :> Get '[HTML] Html

bioServer :: Connection -> Server BioApi
bioServer conn h = do
  rows <- liftIO (query conn "SELECT handle, bio FROM profiles WHERE handle = ?" (Only h))
  case rows of
    (p:_) -> pure (profilePage p)
    []    -> throwError err404

profilePage :: Profile -> Html
profilePage p = H.docTypeHtml $ do
  H.head (H.title (toHtml (handle p)))
  H.body $ H.div ! A.class_ "profile" $ do
    H.h1 (toHtml (handle p))
    H.p (preEscapedToHtml (bio p))
