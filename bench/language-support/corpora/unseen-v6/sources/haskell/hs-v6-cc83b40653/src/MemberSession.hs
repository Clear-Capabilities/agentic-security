{-# LANGUAGE OverloadedStrings #-}
module MemberSession (main) where

import Control.Monad.IO.Class (liftIO)
import Crypto.Random (getRandomBytes)
import qualified Data.ByteArray.Encoding as BA
import qualified Data.ByteString as BS
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Lazy as TL
import Web.Scotty
import Web.Scotty.Cookie (setSimpleCookie)
import qualified Members

main :: IO ()
main = scotty 8080 $
  post "/members/login" $ do
    email <- param "email"
    password <- param "password"
    accepted <- liftIO (Members.verify (TL.toStrict email) (TL.toStrict password))
    if accepted
      then do
        bytes <- liftIO (getRandomBytes 24 :: IO BS.ByteString)
        let token = TE.decodeLatin1 (BA.convertToBase BA.Base64URLUnpadded bytes)
        liftIO (Members.storeSession (TL.toStrict email) token)
        setSimpleCookie "member_session" token
        redirect "/members/home"
      else text "sign in failed"
