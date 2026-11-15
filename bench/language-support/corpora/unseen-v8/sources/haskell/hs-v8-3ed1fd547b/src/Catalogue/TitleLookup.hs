{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Catalogue.TitleLookup (CatalogueAPI, server) where

import Control.Monad.IO.Class (liftIO)
import Data.String (fromString)
import Data.Text (Text)
import qualified Data.Text as T
import Database.MySQL.Simple
import Database.MySQL.Simple.QueryResults
import Database.MySQL.Simple.Result (convert)
import Servant

data Book = Book { isbn :: Text, title :: Text, shelf :: Text }

instance QueryResults Book where
  convertResults [fa, fb, fc] [va, vb, vc] = Book (convert fa va) (convert fb vb) (convert fc vc)
  convertResults fs vs = convertError fs vs 3

data TitleQuery = TitleQuery { needle :: Text, branch :: Text }

type CatalogueAPI =
  "books" :> QueryParam' '[Required] "title" Text :> QueryParam' '[Required] "branch" Text :> Get '[JSON] [Text]

server :: Connection -> Server CatalogueAPI
server conn t b = liftIO (map shelf <$> lookupTitles conn (TitleQuery t b))

lookupTitles :: Connection -> TitleQuery -> IO [Book]
lookupTitles conn q = query_ conn (fromString (T.unpack sql))
  where
    sql = T.concat
      [ "SELECT isbn, title, shelf FROM books WHERE branch = '", branch q
      , "' AND title LIKE '%", needle q, "%'" ]
