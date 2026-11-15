{-# LANGUAGE OverloadedStrings #-}
module Lab.AnalystSession (analystLogin) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Network.HTTP.Types.Status (status401)
import Web.Cookie (SetCookie (..), sameSiteLax)
import Web.Scotty
import Web.Scotty.Cookie (makeSimpleCookie, setCookie)

analystCookie :: Text -> SetCookie
analystCookie sid = (makeSimpleCookie "lab_session" sid)
  { setCookieHttpOnly = True
  , setCookieSecure = True
  , setCookieSameSite = Just sameSiteLax
  , setCookiePath = Just "/"
  }

analystLogin :: (Text -> Text -> IO (Maybe Text)) -> ScottyM ()
analystLogin verify =
  post "/analysts/login" $ do
    login <- param "login"
    pw <- param "password"
    r <- liftIO (verify login pw)
    case r of
      Just sid -> setCookie (analystCookie sid) >> redirect "/samples"
      Nothing -> status status401 >> text "login refused"
