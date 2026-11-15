{-# LANGUAGE OverloadedStrings #-}
module Orchestra.BoxOfficeLogin (loginRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import Network.HTTP.Types.Status (status401)
import Web.Scotty

loginRoutes :: (TL.Text -> TL.Text -> IO (Maybe TL.Text)) -> ScottyM ()
loginRoutes authenticate =
  post "/box-office/login" $ do
    user <- param "user"
    pass <- param "password"
    result <- liftIO (authenticate user pass)
    case result of
      Nothing -> status status401 >> text "login failed"
      Just sessionId -> do
        setHeader "Set-Cookie" ("boxoffice_session=" <> sessionId <> "; Path=/")
        redirect "/box-office"
