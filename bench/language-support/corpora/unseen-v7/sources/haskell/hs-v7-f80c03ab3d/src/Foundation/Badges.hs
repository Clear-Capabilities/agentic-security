{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
module Foundation.Badges where

import Yesod.Core
import Yesod.Auth

import Badges.Types (BadgeId)

data App = App

mkYesodData "App" [parseRoutes|
/                        HomeR        GET
/auth                    AuthR        Auth getAuth
/badges                  BadgesR      GET POST
/badges/#BadgeId         BadgeR       GET
/badges/#BadgeId/revoke  BadgeRevokeR POST
|]

requireOperator :: Handler AuthResult
requireOperator = do
  mu <- maybeAuthId
  pure (maybe AuthenticationRequired (const Authorized) mu)

instance Yesod App where
  isAuthorized HomeR _ = pure Authorized
  isAuthorized (AuthR _) _ = pure Authorized
  isAuthorized (BadgeRevokeR _) _ = pure Authorized
  isAuthorized _ _ = requireOperator
