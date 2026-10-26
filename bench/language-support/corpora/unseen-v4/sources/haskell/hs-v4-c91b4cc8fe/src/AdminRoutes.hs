{-# LANGUAGE OverloadedStrings #-}
module AdminRoutes (adminApp) where

import Web.Scotty
import Network.HTTP.Types.Status (status401)
import Database.SQLite.Simple
import qualified Data.Text.Lazy as TL

requireAdmin :: String -> ActionM ()
requireAdmin adminToken = do
  hdr <- header "Authorization"
  case hdr of
    Just v | TL.unpack v == "Bearer " ++ adminToken -> pure ()
    _ -> status status401 >> text "unauthorized" >> finish

adminApp :: String -> Connection -> ScottyM ()
adminApp adminToken conn = do
  get "/health" (text "ok")
  post "/admin/users/:id/delete" $ do
    requireAdmin adminToken
    uid <- param "id" :: ActionM Int
    liftAndCatchIO (execute conn "DELETE FROM users WHERE id = ?" (Only uid))
    text "deleted"
