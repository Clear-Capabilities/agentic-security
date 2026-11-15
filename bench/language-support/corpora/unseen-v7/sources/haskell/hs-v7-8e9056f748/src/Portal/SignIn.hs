{-# LANGUAGE OverloadedStrings #-}
module Portal.SignIn (signInRoutes) where

import Control.Monad.IO.Class (liftIO)
import Crypto.BCrypt (validatePassword)
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Lazy as TL
import Network.HTTP.Types.Status (status401)
import System.Entropy (getEntropy)
import Web.Scotty
import Web.Scotty.Cookie (setSimpleCookie)

import Portal.Accounts (Account(..), lookupAccount, storeSession)

signInRoutes :: ScottyM ()
signInRoutes =
  post "/signin" $ do
    login <- param "login"
    pw <- param "password"
    found <- liftIO (lookupAccount (TL.toStrict login))
    case found of
      Just acct | validatePassword (accountHash acct) (TE.encodeUtf8 (TL.toStrict pw)) -> do
        token <- liftIO (TE.decodeUtf8 . B16.encode <$> getEntropy 32)
        liftIO (storeSession (accountId acct) token)
        setSimpleCookie "session" token
        redirect "/dashboard"
      _ -> status status401 >> text "login failed"
