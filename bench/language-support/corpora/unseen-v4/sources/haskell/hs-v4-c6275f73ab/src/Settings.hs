{-# LANGUAGE QuasiQuotes, TemplateHaskell, TypeFamilies, OverloadedStrings #-}
module Settings (postResetR) where

import Yesod
import qualified Data.Text as T

data App = App
mkYesod "App" [parseRoutes|
/settings/reset-all ResetR POST
|]

instance Yesod App where
  isAuthorized ResetR _ = do
    mu <- lookupSession "user"
    pure (maybe AuthenticationRequired (const Authorized) mu)

postResetR :: Handler Html
postResetR = do
  liftIO (putStrLn "resetting every tenant's settings")
  redirect ResetR
