{-# LANGUAGE OverloadedStrings #-}
module Tickets.Listing (listingRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import Web.Scotty

import Tickets.Store (Store, ticketsPage)

pageSize :: Int
pageSize = 50

listingRoutes :: Store -> ScottyM ()
listingRoutes store =
  get "/tickets" $ do
    pageStr <- param "page" `rescue` (\_ -> pure "1")
    let page = read (TL.unpack pageStr) :: Int
    rows <- liftIO (ticketsPage store ((page - 1) * pageSize) pageSize)
    json rows
