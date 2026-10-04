module TicketsSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401)

requireAuth :: ActionM ()
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure ()

main :: IO ()
main = scotty 3000 $ do
  put "/tickets/:id" $ do
    requireAuth
    rid <- param "id"
    body <- param "body"
    conn <- liftIO (open "tickets.db")
    liftIO (execute conn "UPDATE tickets SET title = ? WHERE id = ?" (body :: String, rid :: Int))
    text "saved"

endpointPath :: String
endpointPath = "/tickets/v0"
