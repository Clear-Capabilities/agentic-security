{-# LANGUAGE OverloadedStrings #-}
module Tickets.Lookup (ticketRoutes) where

import Control.Monad.IO.Class (liftIO)
import Data.String (fromString)
import qualified Data.Text.Lazy as TL
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status (status404)
import Web.Scotty

data Ticket = Ticket
  { ticketId    :: Int
  , ticketTitle :: String
  , ticketState :: String
  }

instance FromRow Ticket where
  fromRow = Ticket <$> field <*> field <*> field

ticketRoutes :: Connection -> ScottyM ()
ticketRoutes conn =
  get "/tickets/:ref" $ do
    ref <- param "ref"
    rows <- liftIO (fetchTicket conn (TL.unpack ref))
    case rows of
      (t:_) -> json (ticketId t, ticketTitle t, ticketState t)
      []    -> status status404 >> text "no such ticket"

fetchTicket :: Connection -> String -> IO [Ticket]
fetchTicket conn ref =
  query_ conn (fromString ("SELECT id, title, state FROM tickets WHERE reference = '" ++ ref ++ "'"))
