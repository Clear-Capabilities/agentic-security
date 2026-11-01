{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module ProfileCard (CardApi, cardServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text as T
import Database.PostgreSQL.Simple
import Servant

data Profile = Profile { handle :: Text, bio :: Text }

instance FromRow Profile where
  fromRow = Profile <$> field <*> field

type CardApi = "members" :> Capture "handle" Text :> "card" :> Get '[PlainText] Text

escapeHtml :: Text -> Text
escapeHtml = T.concatMap esc
  where
    esc '<'  = "&lt;"
    esc '>'  = "&gt;"
    esc '&'  = "&amp;"
    esc '"'  = "&quot;"
    esc '\'' = "&#39;"
    esc c    = T.singleton c

cardServer :: Connection -> Server CardApi
cardServer conn h = do
  rows <- liftIO (query conn "SELECT handle, bio FROM profiles WHERE handle = ?" (Only h))
  case rows of
    (p:_) -> pure (renderCard p)
    []    -> throwError err404

renderCard :: Profile -> Text
renderCard p = T.concat
  [ "<div class=\"card\"><h2>", escapeHtml (handle p), "</h2>"
  , "<p>", escapeHtml (bio p), "</p></div>"
  ]
