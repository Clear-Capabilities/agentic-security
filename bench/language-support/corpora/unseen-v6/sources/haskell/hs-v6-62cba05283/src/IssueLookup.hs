{-# LANGUAGE OverloadedStrings #-}
module IssueLookup (main) where

import Control.Lens ((^.))
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Network.Wreq as Wreq
import Text.Read (readMaybe)
import Web.Spock
import Web.Spock.Config

trackerBase :: String
trackerBase = "https://tracker.internal.example.com/api/issues/"

main :: IO ()
main = do
  cfg <- defaultSpockCfg () PCNoDatabase ()
  runSpock 8080 $ spock cfg $
    post ("slack" <//> "issue") $ do
      command <- param' "text"
      case readMaybe (T.unpack (T.strip command)) :: Maybe Int of
        Nothing -> text "usage: /issue <number>"
        Just issueId -> do
          summary <- liftIO (fetchIssue issueId)
          setHeader "Content-Type" "application/json"
          lazyBytes summary

fetchIssue :: Int -> IO BL.ByteString
fetchIssue issueId = do
  response <- Wreq.get (trackerBase ++ show issueId)
  pure (response ^. Wreq.responseBody)
