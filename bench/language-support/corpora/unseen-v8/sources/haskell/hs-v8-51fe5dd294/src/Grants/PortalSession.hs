{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Grants.PortalSession (Credentials (..), LoginAPI, loginServer) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Char8 as B8
import Data.Text (Text)
import Servant
import Web.Cookie (SetCookie (..), defaultSetCookie)
import Web.FormUrlEncoded (FromForm (..), parseUnique)

data Credentials = Credentials { applicantEmail :: Text, applicantPassword :: Text }

instance FromForm Credentials where
  fromForm f = Credentials <$> parseUnique "email" f <*> parseUnique "password" f

type LoginAPI =
  "portal" :> "login" :> ReqBody '[FormUrlEncoded] Credentials
    :> Post '[JSON] (Headers '[Header "Set-Cookie" SetCookie] NoContent)

sessionCookie :: B8.ByteString -> SetCookie
sessionCookie sid = defaultSetCookie { setCookieName = "portal_sid", setCookieValue = sid, setCookiePath = Just "/" }

loginServer :: (Credentials -> IO (Maybe B8.ByteString)) -> Server LoginAPI
loginServer authenticate creds = do
  m <- liftIO (authenticate creds)
  case m of
    Nothing -> throwError err401
    Just sid -> pure (addHeader (sessionCookie sid) NoContent)
