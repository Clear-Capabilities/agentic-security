{-# LANGUAGE OverloadedStrings #-}
module Radio.FeedImport (feedRoutes) where

import Control.Lens ((^.))
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Lazy as TL
import qualified Network.Wreq as Wreq
import Web.Scotty

-- Pulls a partner station's schedule feed and stores it for the planner.
feedRoutes :: (BL.ByteString -> IO ()) -> ScottyM ()
feedRoutes store =
  post "/schedule/import" $ do
    feedUrl <- param "feed"
    feed <- liftIO (fetchFeed (TL.unpack feedUrl))
    liftIO (store feed)
    text "imported"

fetchFeed :: String -> IO BL.ByteString
fetchFeed url = do
  resp <- Wreq.get url
  pure (resp ^. Wreq.responseBody)
