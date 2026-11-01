{-# LANGUAGE OverloadedStrings #-}
module ActivityFeed (feedRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import Database.PostgreSQL.Simple
import Web.Scotty

data Event = Event { eventId :: Int, eventKind :: T.Text, eventActor :: T.Text }

instance FromRow Event where
  fromRow = Event <$> field <*> field <*> field

feedRoutes :: Connection -> ScottyM ()
feedRoutes conn =
  get "/activity" $ do
    requested <- param "limit" `rescue` (\_ -> pure 50)
    events <- liftIO (fetchPage conn requested)
    text (TL.pack (unlines (map describe events)))
  where
    describe e = show (eventId e) <> " " <> T.unpack (eventActor e) <> " " <> T.unpack (eventKind e)

fetchPage :: Connection -> Int -> IO [Event]
fetchPage conn pageSize =
  query conn "SELECT id, kind, actor FROM events ORDER BY id DESC LIMIT ?" (Only pageSize)
