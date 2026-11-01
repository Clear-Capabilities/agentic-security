{-# LANGUAGE OverloadedStrings #-}
module UserAdmin (adminRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status (status404)
import Web.Scotty

adminRoutes :: Connection -> ScottyM ()
adminRoutes conn = do
  get "/admin/users" $ do
    rows <- liftIO (query_ conn "SELECT id, email FROM users ORDER BY id" :: IO [(Int, TL.Text)])
    text (TL.unlines [TL.pack (show i) <> " " <> e | (i, e) <- rows])
  delete "/admin/users/:id" $ do
    userId <- param "id"
    removed <- liftIO (execute conn "DELETE FROM users WHERE id = ?" (Only (userId :: Int)))
    if removed == 0
      then status status404 >> text "no such user"
      else text ("removed user " <> TL.pack (show userId))
