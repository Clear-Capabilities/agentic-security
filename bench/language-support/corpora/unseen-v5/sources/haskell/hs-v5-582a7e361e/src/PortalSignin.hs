{-# LANGUAGE OverloadedStrings, TypeFamilies #-}
module PortalSignin (postPortalSigninR) where

import qualified Data.ByteString.Char8 as B
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Web.Cookie
import Yesod
import Foundation

newtype SigninInput = SigninInput { signinAccount :: Text }

signinForm :: FormInput Handler SigninInput
signinForm = SigninInput <$> ireq textField "account"

postPortalSigninR :: Handler Html
postPortalSigninR = do
  input <- runInputPost signinForm
  token <- lookupToken (signinAccount input)
  setCookie defaultSetCookie
    { setCookieName     = "portal_session"
    , setCookieValue    = token
    , setCookiePath     = Just "/"
    , setCookieHttpOnly = False
    , setCookieSecure   = False
    }
  redirect PortalHomeR

lookupToken :: Text -> Handler B.ByteString
lookupToken account = pure ("p_" <> TE.encodeUtf8 account)
