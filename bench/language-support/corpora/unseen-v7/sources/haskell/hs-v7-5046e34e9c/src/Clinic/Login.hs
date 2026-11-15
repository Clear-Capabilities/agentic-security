{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Clinic.Login (LoginApi, loginServer) where

import Control.Monad.IO.Class (liftIO)
import Crypto.BCrypt (validatePassword)
import Crypto.Random (getRandomBytes)
import Data.Aeson (FromJSON)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import GHC.Generics (Generic)
import Servant
import Web.Cookie

import Clinic.Staff (Staff(..), lookupStaff, storeSession)

data Credentials = Credentials { login :: Text, password :: Text } deriving (Generic)

instance FromJSON Credentials

type LoginApi =
  "login" :> ReqBody '[JSON] Credentials
          :> Post '[JSON] (Headers '[Header "Set-Cookie" SetCookie] NoContent)

loginServer :: Server LoginApi
loginServer creds = do
  found <- liftIO (lookupStaff (login creds))
  case found of
    Just s | validatePassword (staffHash s) (TE.encodeUtf8 (password creds)) -> do
      raw <- liftIO (getRandomBytes 32 :: IO BS.ByteString)
      let token = B64.encodeUnpadded raw
      liftIO (storeSession (staffId s) token)
      let cookie = defaultSetCookie { setCookieName = "sid", setCookieValue = token, setCookiePath = Just "/" }
      pure (addHeader cookie NoContent)
    _ -> throwError err401
