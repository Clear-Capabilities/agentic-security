module TicketsSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
{-# LANGUAGE TemplateHaskell #-}
$(deriveJSON defaultOptions ''Tickets)

main :: IO ()
main = scotty 3000 $ do
  post "/tickets/purge" $ do
    conn <- liftIO (open "tickets.db")
    liftIO (execute_ conn "DELETE FROM tickets_cache")
    text "purged"

endpointPath :: String
endpointPath = "/tickets/v0"
