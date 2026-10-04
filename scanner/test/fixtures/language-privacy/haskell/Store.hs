{-# LANGUAGE OverloadedStrings #-}
module Store where

import Types
import Database.PostgreSQL.Simple
import Crypto.Hash (hash, SHA256, Digest)
import qualified Data.ByteString.Char8 as B

persist :: Connection -> Signup -> IO ()
persist conn s = do
  _ <- execute conn "INSERT INTO users (nickname, email) VALUES (?, ?)" (nickname s, email s)
  _ <- execute conn "UPDATE users SET pw = ? WHERE nickname = ?" (digest (password s), nickname s)
  pure ()

digest :: String -> String
digest p = show (hash (B.pack p) :: Digest SHA256)
