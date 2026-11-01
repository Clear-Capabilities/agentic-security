{-# LANGUAGE OverloadedStrings #-}
module CatalogPaging (catalogRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import Database.SQLite.Simple
import Web.Scotty

pageSize :: Int
pageSize = 24

catalogRoutes :: Connection -> ScottyM ()
catalogRoutes conn =
  get "/catalog" $ do
    pageText <- param "page" `rescue` (\_ -> pure "1")
    let page = read (T.unpack pageText) :: Int
        offset = (page - 1) * pageSize
    rows <- liftIO (query conn "SELECT title FROM products ORDER BY title LIMIT ? OFFSET ?" (pageSize, offset)) :: ActionM [Only T.Text]
    text (TL.fromStrict (T.unlines (map fromOnly rows)))
