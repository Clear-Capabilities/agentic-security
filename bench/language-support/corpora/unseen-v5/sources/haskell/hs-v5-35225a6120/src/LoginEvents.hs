{-# LANGUAGE OverloadedStrings #-}
module LoginEvents (loginRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T
import System.IO (hPutStrLn, stderr)
import Web.Scotty

data Attempt = Attempt { attemptUser :: T.Text, attemptPassword :: T.Text }

checkCredentials :: Attempt -> IO Bool
checkCredentials a = pure (attemptUser a == "demo" && attemptPassword a == "demo-pass")

loginRoutes :: ScottyM ()
loginRoutes =
  post "/login" $ do
    user     <- param "username"
    password <- param "password"
    let attempt = Attempt user password
    accepted <- liftIO (checkCredentials attempt)
    liftIO (hPutStrLn stderr ("login attempt user=" <> T.unpack (attemptUser attempt) <> " accepted=" <> show accepted))
    if accepted then redirect "/dashboard" else redirect "/login?retry=1"
