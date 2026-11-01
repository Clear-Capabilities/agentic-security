{-# LANGUAGE OverloadedStrings #-}
module StaffPortal (postStaffLoginR) where

import Data.Aeson (Value, object, (.=))
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Web.Cookie (SetCookie(..), defaultSetCookie, sameSiteStrict)
import Yesod.Core
import Yesod.Form
import Foundation (Handler)
import qualified Staff

issueSession :: Text -> Handler ()
issueSession token = setCookie defaultSetCookie { setCookieName = "staff_session", setCookieValue = TE.encodeUtf8 token, setCookiePath = Just "/", setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteStrict }

postStaffLoginR :: Handler Value
postStaffLoginR = do
  (badge, pin) <- runInputPost ((,) <$> ireq textField "badge" <*> ireq textField "pin")
  outcome <- liftIO (Staff.openSession badge pin)
  case outcome of
    Left reason -> permissionDenied reason
    Right token -> do
      issueSession token
      returnJson (object ["status" .= ("signed in" :: Text)])
