{-# LANGUAGE OverloadedStrings #-}
module Catalogue.PatronLogin (enrolPatron, patronLogin) where

import Crypto.PasswordStore (makePassword, verifyPassword)
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Database.SQLite.Simple

enrolPatron :: Connection -> Text -> Text -> IO ()
enrolPatron conn cardNo pw = do
  stored <- makePassword (TE.encodeUtf8 pw) 17
  execute conn "INSERT INTO patrons (card_no, pw) VALUES (?, ?)" (cardNo, stored)

patronLogin :: Connection -> Text -> Text -> IO Bool
patronLogin conn cardNo pw = do
  rows <- query conn "SELECT pw FROM patrons WHERE card_no = ?" (Only cardNo) :: IO [Only ByteString]
  pure $ case rows of
    [Only stored] -> verifyPassword (TE.encodeUtf8 pw) stored
    _ -> False
