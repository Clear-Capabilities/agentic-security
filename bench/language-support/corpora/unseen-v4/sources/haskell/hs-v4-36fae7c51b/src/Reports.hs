{-# LANGUAGE OverloadedStrings #-}
module Reports (deleteByTag) where

import Database.SQLite.Simple (Connection, execute)
import Network.Wai (Request, queryString)
import Data.Text.Encoding (decodeUtf8)

-- The only dynamic part of the statement is bound, never spliced.
deleteByTag :: Connection -> Request -> IO ()
deleteByTag conn req =
  case lookup "tag" (queryString req) of
    Just (Just raw) -> execute conn "DELETE FROM notes WHERE tag = ?" [decodeUtf8 raw]
    _               -> pure ()
