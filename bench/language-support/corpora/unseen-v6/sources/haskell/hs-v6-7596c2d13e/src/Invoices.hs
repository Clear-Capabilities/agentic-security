{-# LANGUAGE OverloadedStrings #-}
module Invoices (main) where

import Control.Monad.IO.Class (liftIO)
import Data.String (fromString)
import qualified Data.Text.Lazy as TL
import Database.PostgreSQL.Simple
import Web.Scotty

type InvoiceRow = (Int, TL.Text, Double)

main :: IO ()
main = do
  conn <- connectPostgreSQL "dbname=billing"
  scotty 8080 $ do
    get "/invoices" $ do
      customer <- param "customer"
      rows <- liftIO (query_ conn (fromString ("SELECT id, ref, total FROM invoices WHERE customer_ref = '" ++ TL.unpack customer ++ "' ORDER BY issued_at DESC"))) :: ActionM [InvoiceRow]
      json [ (i, r, t) | (i, r, t) <- rows ]
    get "/invoices/count" $ do
      [Only n] <- liftIO (query_ conn "SELECT count(*) FROM invoices") :: ActionM [Only Int]
      json n
