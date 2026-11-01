{-# LANGUAGE OverloadedStrings, TypeFamilies #-}
module LocalePreference (postLocaleR) where

import qualified Data.ByteString.Char8 as B
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Web.Cookie
import Yesod
import Foundation

newtype LocaleInput = LocaleInput { chosenLocale :: Text }

localeForm :: FormInput Handler LocaleInput
localeForm = LocaleInput <$> ireq textField "locale"

supported :: [Text]
supported = ["en-GB", "en-US", "fr-FR", "de-DE", "ja-JP"]

postLocaleR :: Handler Html
postLocaleR = do
  input <- runInputPost localeForm
  let locale = if chosenLocale input `elem` supported then chosenLocale input else "en-GB"
  setCookie defaultSetCookie
    { setCookieName   = "locale"
    , setCookieValue  = TE.encodeUtf8 locale
    , setCookiePath   = Just "/"
    , setCookieMaxAge = Just (365 * 86400)
    }
  redirect PortalHomeR
