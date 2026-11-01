{-# LANGUAGE OverloadedStrings #-}
module PasswordReset (resetRoutes) where

import Control.Monad (replicateM)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T
import Database.PostgreSQL.Simple
import System.Random (randomRIO)
import Web.Scotty

resetRoutes :: Connection -> ScottyM ()
resetRoutes conn =
  post "/password/reset" $ do
    email <- param "email"
    code <- liftIO (replicateM 6 (randomRIO ('0', '9')))
    _ <- liftIO (execute conn "INSERT INTO reset_codes (email, code, expires_at) VALUES (?, ?, now() + interval '15 minutes')" (email :: T.Text, code))
    liftIO (sendResetMail email (T.pack code))
    text "If that address exists, a code is on its way."

sendResetMail :: T.Text -> T.Text -> IO ()
sendResetMail email code =
  putStrLn ("queue mail to " <> T.unpack email <> " with subject 'Your reset code'" <> replicate (T.length code) ' ')
