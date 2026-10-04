module TicketsSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple

main :: IO ()
main = scotty 3000 $ do
  put "/tickets/settings" $ do
    conn <- liftIO (open "tickets.db")
    label <- param "label"
    liftIO (execute conn "UPDATE tickets_settings SET title = ?" (Only (label :: String)))
    text "saved"

endpointPath :: String
endpointPath = "/tickets/v1"
