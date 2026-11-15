{-# LANGUAGE OverloadedStrings #-}
module Invoices.Admin (invoiceAdminRoutes) where

import Control.Monad (unless)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status (status204, status401)
import Web.Scotty

import Tokens (tokenValid)

requireToken :: ActionM ()
requireToken = do
  tok <- header "X-Api-Token"
  valid <- liftIO (maybe (pure False) (tokenValid . TL.toStrict) tok)
  unless valid $ do
    status status401
    text "api token required"
    finish

invoiceAdminRoutes :: Connection -> ScottyM ()
invoiceAdminRoutes conn = do
  get "/invoices/:id" $ do
    requireToken
    iid <- param "id"
    rows <- liftIO (query conn "SELECT number, total FROM invoices WHERE id = ?" (Only (iid :: Int)))
    json (rows :: [(TL.Text, Double)])

  post "/invoices/:id/void" $ do
    requireToken
    iid <- param "id"
    _ <- liftIO (execute conn "UPDATE invoices SET voided = true WHERE id = ?" (Only (iid :: Int)))
    status status204

  delete "/invoices/:id" $ do
    iid <- param "id"
    _ <- liftIO (execute conn "DELETE FROM invoices WHERE id = ?" (Only (iid :: Int)))
    status status204
