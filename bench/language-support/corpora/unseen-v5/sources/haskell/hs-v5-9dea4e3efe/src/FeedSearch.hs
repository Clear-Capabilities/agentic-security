{-# LANGUAGE OverloadedStrings #-}
module FeedSearch (searchApp) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Network.HTTP.Simple
import Web.Spock

catalogRequest :: Request
catalogRequest = "https://catalog.northwind.internal/feeds/search"

searchFeeds :: Text -> IO BL.ByteString
searchFeeds term = do
  let request = setRequestQueryString [("q", Just (TE.encodeUtf8 term)), ("limit", Just "20")] catalogRequest
  response <- httpLBS request
  pure (getResponseBody response)

searchApp :: SpockM () () () ()
searchApp =
  get "feeds/search" $ do
    term <- param' "q"
    found <- liftIO (searchFeeds (T.strip term))
    setHeader "Content-Type" "application/json"
    lazyBytes found
