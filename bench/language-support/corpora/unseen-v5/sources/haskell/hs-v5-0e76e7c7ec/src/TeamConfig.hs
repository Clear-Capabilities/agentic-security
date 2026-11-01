{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module TeamConfig (ConfigApi, configServer, configContext) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import Servant

newtype Operator = Operator { operatorName :: Text }

type ConfigApi = BasicAuth "operators" Operator :>
  (    "teams" :> Capture "team" Int :> "settings" :> Get '[JSON] [Text]
  :<|> "teams" :> Capture "team" Int :> "settings" :> "reset" :> Post '[JSON] NoContent
  )

configContext :: Connection -> Context '[BasicAuthCheck Operator]
configContext conn = BasicAuthCheck check :. EmptyContext
  where
    check (BasicAuthData user secretBytes) = do
      rows <- query conn "SELECT name FROM operators WHERE name = ? AND api_key = ?" (user, secretBytes) :: IO [Only Text]
      pure (case rows of { (Only n : _) -> Authorized (Operator n); [] -> Unauthorized })

configServer :: Connection -> Server ConfigApi
configServer conn operator = showSettings :<|> resetSettings
  where
    showSettings team = do
      rows <- liftIO (query conn "SELECT name FROM team_settings WHERE team_id = ?" (Only team))
      pure [n | Only n <- rows]
    resetSettings team = do
      _ <- liftIO (execute conn "UPDATE team_settings SET billing_email = '', seat_limit = 5, reset_by = ? WHERE team_id = ?" (operatorName operator, team))
      pure NoContent
