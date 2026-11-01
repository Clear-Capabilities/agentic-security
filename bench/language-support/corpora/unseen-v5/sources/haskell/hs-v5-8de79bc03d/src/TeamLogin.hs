{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module TeamLogin (LoginApi, loginServer) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Servant
import Web.Cookie

type LoginApi = "team" :> "login" :> ReqBody '[JSON] Text :> Post '[JSON] (Headers '[Header "Set-Cookie" Text] NoContent)

loginServer :: Server LoginApi
loginServer member = do
  token <- liftIO (lookupToken member)
  pure (addHeader (renderCookie (authCookie token)) NoContent)

lookupToken :: Text -> IO B.ByteString
lookupToken member = pure ("t_" <> TE.encodeUtf8 member)

authCookie :: B.ByteString -> SetCookie
authCookie token = defaultSetCookie
  { setCookieName  = "team_auth"
  , setCookieValue = token
  , setCookiePath  = Just "/"
  }

renderCookie :: SetCookie -> Text
renderCookie = TE.decodeLatin1 . BL.toStrict . BB.toLazyByteString . renderSetCookie
