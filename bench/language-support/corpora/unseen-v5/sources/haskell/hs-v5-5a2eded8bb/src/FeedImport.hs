{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}
module FeedImport (feedApp) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Network.HTTP.Simple
import Web.Spock

data FeedSource = FeedSource { feedUrl :: Text, feedName :: Text }
  deriving (Generic)

instance FromJSON FeedSource

feedApp :: SpockM () () () ()
feedApp =
  post "feeds/import" $ do
    source <- jsonBody'
    request <- liftIO (parseRequest (T.unpack (feedUrl source)))
    response <- liftIO (httpLBS request)
    let entries = BL.length (getResponseBody response)
    text ("imported " <> feedName source <> " (" <> T.pack (show entries) <> " bytes)")
