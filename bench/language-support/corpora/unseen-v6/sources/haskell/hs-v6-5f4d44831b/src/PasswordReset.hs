{-# LANGUAGE OverloadedStrings #-}
module PasswordReset (main) where

import Control.Monad (replicateM)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import Database.SQLite.Simple
import Network.Mail.Mime (Address(..), renderSendMail, simpleMail')
import System.Random (randomRIO)
import Web.Scotty

main :: IO ()
main = do
  conn <- open "accounts.db"
  scotty 8080 $
    post "/password/reset" $ do
      email <- param "email"
      code <- liftIO (replicateM 6 (randomRIO ('0', '9')))
      liftIO (execute conn "INSERT INTO reset_codes (email, code) VALUES (?, ?)" (email :: TL.Text, code))
      liftIO (sendResetMail email code)
      text "if the address is known, a code has been sent"

sendResetMail :: TL.Text -> String -> IO ()
sendResetMail email code =
  renderSendMail (simpleMail' (Address Nothing (TL.toStrict email)) sender "Password reset" ("Your reset code is " <> TL.pack code))
  where
    sender = Address (Just "Accounts") "no-reply@example.com"
