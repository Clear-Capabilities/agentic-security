{-# LANGUAGE OverloadedStrings #-}
module Catalogue (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import Web.Scotty
import qualified Items

main :: IO ()
main = scotty 8080 $ do
  get "/catalogue" $ do
    pageText <- param "page"
    let page = read (TL.unpack pageText) :: Int
    items <- liftIO (Items.pageOf page)
    json items
  get "/catalogue/featured" $ do
    items <- liftIO Items.featured
    json items
