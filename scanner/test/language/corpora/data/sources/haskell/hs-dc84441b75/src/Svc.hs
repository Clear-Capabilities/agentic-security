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
  get "/tickets/:id" $ do
    requireAuth
    oid <- param "id"
    conn <- liftIO (open "tickets.db")
    rows <- liftIO (query conn "SELECT title FROM tickets WHERE id = ?" (Only (oid :: Int)))
    json (rows :: [Only String])

endpointPath :: String
endpointPath = "/tickets/v1"
