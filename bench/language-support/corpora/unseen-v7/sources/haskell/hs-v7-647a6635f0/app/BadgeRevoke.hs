{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad (forM_, unless)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Database.SQLite.Simple

main :: IO ()
main = do
  conn <- open "badges.db"
  contents <- TIO.getContents
  forM_ (T.lines contents) $ \line -> do
    let serial = T.strip line
    unless (T.null serial) (revoke conn serial)
  close conn

revoke :: Connection -> T.Text -> IO ()
revoke conn serial = do
  executeNamed conn "UPDATE badges SET revoked = 1, revoked_at = datetime('now') WHERE serial = :serial" [":serial" := serial]
  n <- changes conn
  TIO.putStrLn (serial <> ": " <> T.pack (show n) <> " row(s) updated")
