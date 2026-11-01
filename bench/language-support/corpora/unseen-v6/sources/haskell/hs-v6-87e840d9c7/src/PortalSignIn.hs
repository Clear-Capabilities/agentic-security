{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module PortalSignIn (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import GHC.Generics (Generic)
import Servant
import Web.Cookie (SetCookie(..), defaultSetCookie)
import qualified Portal

data SignIn = SignIn { email :: Text, password :: Text } deriving (Show, Generic)
instance FromJSON SignIn

type API = "portal" :> "sign-in" :> ReqBody '[JSON] SignIn
  :> Post '[JSON] (Headers '[Header "Set-Cookie" SetCookie] NoContent)

signInHandler :: SignIn -> Handler (Headers '[Header "Set-Cookie" SetCookie] NoContent)
signInHandler creds = do
  session <- liftIO (Portal.openSession (email creds) (password creds))
  case session of
    Nothing -> throwError err401 { errBody = "invalid credentials" }
    Just token -> do
      let cookie = defaultSetCookie { setCookieName = "portal_session", setCookieValue = TE.encodeUtf8 token, setCookiePath = Just "/" }
      pure (addHeader cookie NoContent)

app :: Application
app = serve (Proxy :: Proxy API) signInHandler
