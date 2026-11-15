{-# LANGUAGE OverloadedStrings #-}
module Handler.Signin (postSigninR) where

import Crypto.Scrypt (EncryptedPass(..), Pass(..), verifyPass')
import qualified Data.Text.Encoding as TE
import Database.Persist (Entity(..), getBy)
import Yesod.Core
import Yesod.Form (ireq, passwordField, runInputPost, textField)
import Yesod.Persist (runDB)

import Foundation
import Model

postSigninR :: Handler Value
postSigninR = do
  login <- runInputPost (ireq textField "login")
  pw <- runInputPost (ireq passwordField "password")
  found <- runDB (getBy (UniqueOperatorLogin login))
  case found of
    Just (Entity oid op)
      | verifyPass' (Pass (TE.encodeUtf8 pw)) (EncryptedPass (operatorPassword op)) -> do
          setSession "operator" (toPathPiece oid)
          returnJson (object ["signedIn" .= True])
    _ -> permissionDenied "login failed"
