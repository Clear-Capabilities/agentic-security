{-# LANGUAGE OverloadedStrings #-}
module SignIn (signInRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import Web.Scotty

data Session = Session { sessionToken :: TL.Text, sessionUser :: TL.Text }

issueSession :: TL.Text -> IO Session
issueSession user = pure (Session ("s_" <> TL.reverse user <> "_2026") user)

signInRoutes :: ScottyM ()
signInRoutes =
  post "/sign-in" $ do
    user <- param "username"
    session <- liftIO (issueSession user)
    setHeader "Set-Cookie" ("session=" <> sessionToken session <> "; Path=/; Max-Age=86400")
    redirect "/dashboard"
