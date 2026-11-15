{-# LANGUAGE OverloadedStrings #-}
module Grants.ReviewQueue (reviewQueue) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (encode)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import Happstack.Server

maxPageSize :: Int
maxPageSize = 100

reviewQueue :: Connection -> ServerPart Response
reviewQueue conn = dir "reviews" $ dir "queue" $ do
  method GET
  requested <- lookRead "limit"
  let pageSize = max 1 (min maxPageSize requested)
  titles <- liftIO (query conn "SELECT title FROM applications WHERE status = 'submitted' ORDER BY submitted_at LIMIT ?" (Only pageSize))
  ok (toResponseBS "application/json" (encode (map fromOnly (titles :: [Only Text]))))
