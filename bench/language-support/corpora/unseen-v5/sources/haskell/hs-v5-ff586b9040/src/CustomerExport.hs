{-# LANGUAGE OverloadedStrings #-}
module CustomerExport (exportSite) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Char8 as B
import Database.SQLite.Simple
import Snap.Core

exportSite :: Connection -> Snap ()
exportSite conn = route
  [ ("/customers/export.csv", method GET (exportHandler conn))
  , ("/ping", writeBS "pong")
  ]

exportHandler :: Connection -> Snap ()
exportHandler conn = do
  modifyResponse (setContentType "text/csv")
  modifyResponse (setHeader "Content-Disposition" "attachment; filename=customers.csv")
  csv <- liftIO (customerCsv conn)
  writeBS csv

customerCsv :: Connection -> IO B.ByteString
customerCsv conn = do
  rows <- query_ conn "SELECT name, email, phone FROM customers ORDER BY name" :: IO [(String, String, String)]
  pure (B.pack (unlines ("name,email,phone" : [n <> "," <> e <> "," <> p | (n, e, p) <- rows])))
