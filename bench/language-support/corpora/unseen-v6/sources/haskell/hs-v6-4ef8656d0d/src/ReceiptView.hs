{-# LANGUAGE OverloadedStrings #-}
module ReceiptView (main) where

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
    get "/receipts/:id" $ do
      user <- requireUser
      receiptId <- param "id" :: ActionM Int
      rows <- liftIO (query conn "SELECT id, merchant, total FROM receipts WHERE id = ? AND owner_id = ?" (receiptId, user)) :: ActionM [(Int, String, Double)]
      case rows of
        [(i, m, t)] -> json (object ["id" .= i, "merchant" .= m, "total" .= t])
        _ -> status status404 >> text "no such receipt"

requireUser :: ActionM Int
requireUser = do
  auth <- header "Authorization"
  user <- liftIO (maybe (pure Nothing) (Sessions.userIdFor . TL.toStrict) auth)
  maybe (status status401 >> text "sign in required" >> finish) pure user
