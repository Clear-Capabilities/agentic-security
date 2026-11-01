{-# LANGUAGE OverloadedStrings #-}
module Listings (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import Network.HTTP.Types.Status (status400)
import Text.Read (readMaybe)
import Web.Scotty
import qualified Items

main :: IO ()
main = scotty 8080 $ do
  get "/listings" $ do
    pageText <- param "page"
    case readMaybe (TL.unpack pageText) :: Maybe Int of
      Nothing -> status status400 >> text "page must be a whole number"
      Just page -> liftIO (Items.pageOf page) >>= json
  get "/listings/featured" $ do
    items <- liftIO Items.featured
    json items
