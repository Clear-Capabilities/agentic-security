{-# LANGUAGE OverloadedStrings #-}
module UserManagement (managementRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status (status401, status404)
import Web.Scotty

requireAdmin :: Connection -> ActionM ()
requireAdmin conn = do
  token <- header "Authorization"
  rows <- case token of
    Nothing -> pure []
    Just t  -> liftIO (query conn "SELECT id FROM admins WHERE api_token = ? AND revoked_at IS NULL" (Only (TL.toStrict t)) :: IO [Only Int])
  case rows of
    (_:_) -> pure ()
    []    -> status status401 >> text "administrator token required" >> finish

managementRoutes :: Connection -> ScottyM ()
managementRoutes conn = do
  get "/admin/users" $ do
    requireAdmin conn
    rows <- liftIO (query_ conn "SELECT id, email FROM users ORDER BY id" :: IO [(Int, TL.Text)])
    text (TL.unlines [TL.pack (show i) <> " " <> e | (i, e) <- rows])
  delete "/admin/users/:id" $ do
    requireAdmin conn
    userId <- param "id"
    removed <- liftIO (execute conn "DELETE FROM users WHERE id = ?" (Only (userId :: Int)))
    if removed == 0
      then status status404 >> text "no such user"
      else text ("removed user " <> TL.pack (show userId))
