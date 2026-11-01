{-# LANGUAGE OverloadedStrings, TypeFamilies #-}
module MemberSignin (postMemberSigninR) where

import Crypto.PasswordStore (verifyPassword)
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Yesod
import Foundation
import Model

data Credentials = Credentials { credEmail :: Text, credPassword :: Text }

credentialsForm :: FormInput Handler Credentials
credentialsForm = Credentials <$> ireq emailField "email" <*> ireq passwordField "password"

postMemberSigninR :: Handler Html
postMemberSigninR = do
  creds <- runInputPost credentialsForm
  found <- runDB (getBy (UniqueMemberEmail (credEmail creds)))
  case found of
    Just (Entity mid m) | matches (credPassword creds) (memberDigest m) -> do
      setSession "member" (toPathPiece mid)
      redirect HomeR
    _ -> do
      setMessage "Email or password not recognised"
      redirect MemberSigninR

matches :: Text -> BS.ByteString -> Bool
matches pw stored = verifyPassword (TE.encodeUtf8 pw) stored
