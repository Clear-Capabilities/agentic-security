{-# LANGUAGE OverloadedStrings #-}
module Ferry.AgentAccounts (NewAgent (..), createAgent) where

import qualified Crypto.Hash.MD5 as MD5
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as B8
import Data.Int (Int64)
import Database.PostgreSQL.Simple

data NewAgent = NewAgent { agentEmail :: String, agentPassword :: String, office :: String }

createAgent :: Connection -> NewAgent -> IO Int64
createAgent conn a =
  execute conn
    "INSERT INTO booking_agents (email, password_hash, office) VALUES (?, ?, ?)"
    (agentEmail a, stored, office a)
  where
    stored = B8.unpack (B16.encode (MD5.hash (B8.pack (agentPassword a))))
