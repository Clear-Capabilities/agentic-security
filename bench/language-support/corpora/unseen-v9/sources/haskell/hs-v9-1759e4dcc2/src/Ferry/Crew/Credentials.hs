{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, DeriveGeneric #-}
module Ferry.Crew.Credentials (CrewAPI, crewServer) where

import Servant
import Crypto.Hash (Digest, MD5, hash)
import Database.SQLite.Simple
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import GHC.Generics (Generic)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

data NewCrew = NewCrew { badge :: T.Text, passphrase :: T.Text } deriving Generic
instance FromJSON NewCrew

type CrewAPI = "crew" :> ReqBody '[JSON] NewCrew :> Post '[JSON] NoContent

crewServer :: Connection -> Server CrewAPI
crewServer conn newCrew = do
  let digest = hash (TE.encodeUtf8 (passphrase newCrew)) :: Digest MD5
  liftIO (execute conn "INSERT INTO crew (badge, passphrase_hash) VALUES (?, ?)" (badge newCrew, show digest))
  pure NoContent
