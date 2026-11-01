{-# LANGUAGE OverloadedStrings, TypeFamilies #-}
module MemberLogin (postMemberLoginR) where

import Crypto.Hash (SHA1 (..), hashWith)
import qualified Data.ByteArray.Encoding as BA
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Yesod
import Foundation
import Model

data Credentials = Credentials { credEmail :: Text, credPassword :: Text }

credentialsForm :: FormInput Handler Credentials
credentialsForm = Credentials <$> ireq emailField "email" <*> ireq passwordField "password"

postMemberLoginR :: Handler Html
postMemberLoginR = do
  creds <- runInputPost credentialsForm
  found <- runDB (getBy (UniqueMemberEmail (credEmail creds)))
  case found of
    Just (Entity mid m) | memberDigest m == digestFor (credPassword creds) -> do
      setSession "member" (toPathPiece mid)
      redirect HomeR
    _ -> do
      setMessage "Email or password not recognised"
      redirect MemberLoginR

digestFor :: Text -> BS.ByteString
digestFor pw = BA.convertToBase BA.Base16 (hashWith SHA1 (TE.encodeUtf8 pw))
