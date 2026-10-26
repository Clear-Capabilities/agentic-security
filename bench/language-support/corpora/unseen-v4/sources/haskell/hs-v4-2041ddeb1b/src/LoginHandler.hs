{-# LANGUAGE OverloadedStrings #-}
module LoginHandler (login) where

import Web.Scotty
import System.IO (hPutStrLn, stderr)
import qualified Data.Text.Lazy as TL

login :: ActionM ()
login = do
  user <- param "user" :: ActionM String
  password <- param "password" :: ActionM String
  liftAndCatchIO (hPutStrLn stderr ("login attempt: user=" ++ user ++ " password=" ++ password))
  text "checking"
