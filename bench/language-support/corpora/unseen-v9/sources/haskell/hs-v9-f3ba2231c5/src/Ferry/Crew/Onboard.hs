{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, DeriveGeneric #-}
module Ferry.Crew.Onboard (OnboardAPI, onboardServer) where

import Servant
import Crypto.Scrypt (encryptPassIO, defaultParams, Pass(..), getEncryptedPass)
import Database.SQLite.Simple
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import GHC.Generics (Generic)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

data NewCrew = NewCrew { badge :: T.Text, passphrase :: T.Text } deriving Generic
instance FromJSON NewCrew

type OnboardAPI = "crew" :> ReqBody '[JSON] NewCrew :> Post '[JSON] NoContent

onboardServer :: Connection -> Server OnboardAPI
onboardServer conn newCrew = do
  encrypted <- liftIO (encryptPassIO defaultParams (Pass (TE.encodeUtf8 (passphrase newCrew))))
  liftIO (execute conn "INSERT INTO crew (badge, passphrase_hash) VALUES (?, ?)" (badge newCrew, TE.decodeUtf8 (getEncryptedPass encrypted)))
  pure NoContent
