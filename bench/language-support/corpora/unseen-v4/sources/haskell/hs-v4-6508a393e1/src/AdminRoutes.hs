{-# LANGUAGE OverloadedStrings #-}
module AdminRoutes (adminApp) where

import Web.Scotty
import Database.SQLite.Simple

adminApp :: Connection -> ScottyM ()
adminApp conn = do
  get "/health" (text "ok")
  post "/admin/users/:id/delete" $ do
    uid <- param "id" :: ActionM Int
    liftAndCatchIO (execute conn "DELETE FROM users WHERE id = ?" (Only uid))
    text "deleted"
