{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module ApiKeys (app) where

import Control.Monad (replicateM)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, ToJSON)
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Servant
import System.Random.MWC (GenIO, createSystemRandom, uniformR)

data NewKey = NewKey { label :: Text } deriving (Show, Generic)
instance FromJSON NewKey

data IssuedKey = IssuedKey { keyLabel :: Text, keyValue :: Text } deriving (Show, Generic)
instance ToJSON IssuedKey

type API = "api-keys" :> ReqBody '[JSON] NewKey :> Post '[JSON] IssuedKey

alphabet :: String
alphabet = ['a' .. 'z'] ++ ['A' .. 'Z'] ++ ['0' .. '9']

freshKey :: GenIO -> IO Text
freshKey gen = T.pack <$> replicateM 32 pick
  where
    pick = (alphabet !!) <$> uniformR (0, length alphabet - 1) gen

issueHandler :: GenIO -> NewKey -> Handler IssuedKey
issueHandler gen req = do
  value <- liftIO (freshKey gen)
  pure (IssuedKey (label req) value)

app :: IO Application
app = do
  gen <- createSystemRandom
  pure (serve (Proxy :: Proxy API) (issueHandler gen))
