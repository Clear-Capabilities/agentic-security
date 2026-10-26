{-# LANGUAGE OverloadedStrings #-}
module Reports (deleteByTag) where

import Database.SQLite.Simple (Connection, execute_, Query(..))
import qualified Data.Text as T
import Network.Wai (Request, queryString)
import Data.Maybe (fromMaybe)
import Data.Text.Encoding (decodeUtf8)

deleteByTag :: Connection -> Request -> IO ()
deleteByTag conn req = do
  let tag = maybe "" decodeUtf8 . fromMaybe Nothing . lookup "tag" $ queryString req
      stmt = Query $ T.concat ["DELETE FROM notes WHERE tag = '", tag, "'"]
  execute_ conn stmt
