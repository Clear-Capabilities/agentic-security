{-# LANGUAGE OverloadedStrings #-}
module Portal.Login (loginRoutes) where

import Control.Monad.IO.Class (liftIO)
import Crypto.Hash.Algorithms (SHA256(..))
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import Data.ByteArray (constEq)
import Data.ByteString (ByteString)
import qualified Data.Text.Encoding as TE
import Network.HTTP.Types.Status (status401)
import Web.Spock

import Portal.Accounts (Account(..), lookupAccount)

loginRoutes :: SpockM () () () ()
loginRoutes =
  post "login" $ do
    login <- param' "login"
    pw <- param' "password"
    found <- liftIO (lookupAccount login)
    case found of
      Just acct | derive (TE.encodeUtf8 pw) (accountSalt acct) `constEq` accountHash acct ->
        text "welcome"
      _ -> setStatus status401 >> text "login failed"

derive :: ByteString -> ByteString -> ByteString
derive pw salt = PBKDF2.generate (PBKDF2.prfHMAC SHA256) (PBKDF2.Parameters 10 32) pw salt
