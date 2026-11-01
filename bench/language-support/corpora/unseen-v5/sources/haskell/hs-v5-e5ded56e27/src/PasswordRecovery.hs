{-# LANGUAGE OverloadedStrings #-}
module PasswordRecovery (recoveryRoutes) where

import Control.Monad.IO.Class (liftIO)
import Crypto.Random (getRandomBytes)
import qualified Data.ByteArray.Encoding as BA
import qualified Data.ByteString as BS
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple
import Web.Scotty

recoveryRoutes :: Connection -> ScottyM ()
recoveryRoutes conn =
  post "/password/recover" $ do
    email <- param "email"
    raw <- liftIO (getRandomBytes 24 :: IO BS.ByteString)
    let code = TE.decodeLatin1 (BA.convertToBase BA.Base64URLUnpadded raw)
    _ <- liftIO (execute conn "INSERT INTO reset_codes (email, code, expires_at) VALUES (?, ?, now() + interval '15 minutes')" (email :: T.Text, code))
    liftIO (sendRecoveryMail email code)
    text "If that address exists, a code is on its way."

sendRecoveryMail :: T.Text -> T.Text -> IO ()
sendRecoveryMail email code =
  putStrLn ("queue mail to " <> T.unpack email <> " with subject 'Your recovery code'" <> replicate (T.length code) ' ')
