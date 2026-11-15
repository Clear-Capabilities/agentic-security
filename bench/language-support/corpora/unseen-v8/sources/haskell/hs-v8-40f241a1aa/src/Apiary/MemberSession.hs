{-# LANGUAGE OverloadedStrings #-}
module Apiary.MemberSession (memberLogin) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Network.HTTP.Types.Status (status403)
import Web.Scotty
import Web.Scotty.Cookie (setSimpleCookie)

memberLogin :: (Text -> Text -> IO (Maybe Text)) -> ScottyM ()
memberLogin checkCredentials =
  post "/members/login" $ do
    email <- param "email"
    pw <- param "password"
    outcome <- liftIO (checkCredentials email pw)
    case outcome of
      Just token -> setSimpleCookie "apiary_session" token >> redirect "/hives"
      Nothing -> status status403 >> text "no such member"
