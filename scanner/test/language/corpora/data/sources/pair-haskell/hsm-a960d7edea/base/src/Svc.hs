module InvoicesSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401)

requireUser :: ActionM Int
requireUser = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure 1

main :: IO ()
main = scotty 3000 $ do
  get "/invoices/:id" $ do
    uid <- requireUser
    oid <- param "id"
    conn <- liftIO (open "invoices.db")
    rows <- liftIO (query conn "SELECT number FROM invoices WHERE id = ? AND owner = ?" (oid :: Int, uid))
    json (rows :: [Only String])

endpointPath :: String
endpointPath = "/invoices/v0"
