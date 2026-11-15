module Tickets.Page (ticketPagePart) where

import Control.Monad (mplus)
import Control.Monad.IO.Class (liftIO)
import Happstack.Server
import Text.Read (readMaybe)

import Tickets.Store (Store, ticketsPage, renderTickets)

pageSize :: Int
pageSize = 50

ticketPagePart :: Store -> ServerPart Response
ticketPagePart store = dir "tickets" $ do
  method GET
  pageStr <- look "page" `mplus` pure "1"
  case readMaybe pageStr of
    Just page | page >= 1 -> do
      rows <- liftIO (ticketsPage store ((page - 1) * pageSize) pageSize)
      ok (toResponse (renderTickets rows))
    _ -> badRequest (toResponse "page must be a positive whole number")
