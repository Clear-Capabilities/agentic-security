{-# LANGUAGE OverloadedStrings #-}
module InvoiceView (main) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (object, (.=))
import qualified Data.Text.Lazy as TL
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status (status401, status404)
import Web.Scotty
import qualified Sessions

main :: IO ()
main = do
  conn <- connectPostgreSQL "dbname=billing"
  scotty 8080 $
    get "/invoices/:id" $ do
      _user <- requireUser
      invoiceId <- param "id" :: ActionM Int
      rows <- liftIO (query conn "SELECT id, customer, total FROM invoices WHERE id = ?" (Only invoiceId)) :: ActionM [(Int, String, Double)]
      case rows of
        [(i, c, t)] -> json (object ["id" .= i, "customer" .= c, "total" .= t])
        _ -> status status404 >> text "no such invoice"

requireUser :: ActionM Int
requireUser = do
  auth <- header "Authorization"
  user <- liftIO (maybe (pure Nothing) (Sessions.userIdFor . TL.toStrict) auth)
  maybe (status status401 >> text "sign in required" >> finish) pure user
