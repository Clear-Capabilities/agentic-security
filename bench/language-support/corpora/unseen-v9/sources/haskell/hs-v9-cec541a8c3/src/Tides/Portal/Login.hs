{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, DeriveGeneric #-}
module Tides.Portal.Login (LoginAPI, loginServer) where

import Servant
import Crypto.Random (getRandomBytes)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import GHC.Generics (Generic)
import qualified Data.ByteArray.Encoding as BA
import qualified Data.ByteString as BS
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

data Login = Login { station :: T.Text, password :: T.Text } deriving Generic
instance FromJSON Login

type LoginAPI = "portal" :> "session" :> ReqBody '[JSON] Login :> Post '[JSON] T.Text

loginServer :: (T.Text -> T.Text -> IO Bool) -> (T.Text -> T.Text -> IO ()) -> Server LoginAPI
loginServer verify remember login = do
  ok <- liftIO (verify (station login) (password login))
  if not ok
    then throwError err401
    else do
      raw <- liftIO (getRandomBytes 24 :: IO BS.ByteString)
      let sessionId = TE.decodeUtf8 (BA.convertToBase BA.Base64URLUnpadded raw)
      liftIO (remember (station login) sessionId)
      pure sessionId
