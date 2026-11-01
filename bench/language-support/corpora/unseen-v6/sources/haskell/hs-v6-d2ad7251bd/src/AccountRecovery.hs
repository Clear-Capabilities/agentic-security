{-# LANGUAGE OverloadedStrings #-}
module AccountRecovery (main) where

import Control.Monad.IO.Class (liftIO)
import Crypto.Random (getRandomBytes)
import qualified Data.ByteArray.Encoding as BA
import qualified Data.ByteString as BS
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Lazy as TL
import Database.SQLite.Simple
import Network.Mail.Mime (Address(..), renderSendMail, simpleMail')
import Web.Scotty

main :: IO ()
main = do
  conn <- open "accounts.db"
  scotty 8080 $
    post "/account/recover" $ do
      email <- param "email"
      bytes <- liftIO (getRandomBytes 16 :: IO BS.ByteString)
      let code = TE.decodeLatin1 (BA.convertToBase BA.Base16 bytes)
      liftIO (execute conn "INSERT INTO recovery_codes (email, code) VALUES (?, ?)" (email :: TL.Text, code))
      liftIO (renderSendMail (simpleMail' (Address Nothing (TL.toStrict email)) sender "Account recovery" (TL.fromStrict ("Your recovery code is " <> code))))
      text "if the address is known, a code has been sent"
  where
    sender = Address (Just "Accounts") "no-reply@example.com"
