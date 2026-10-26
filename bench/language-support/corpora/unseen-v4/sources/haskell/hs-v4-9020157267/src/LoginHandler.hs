{-# LANGUAGE OverloadedStrings #-}
module LoginHandler (login) where

import Web.Scotty
import System.IO (hPutStrLn, stderr)

login :: ActionM ()
login = do
  user <- param "user" :: ActionM String
  _password <- param "password" :: ActionM String
  liftAndCatchIO (hPutStrLn stderr ("login attempt: user=" ++ user))
  text "checking"
