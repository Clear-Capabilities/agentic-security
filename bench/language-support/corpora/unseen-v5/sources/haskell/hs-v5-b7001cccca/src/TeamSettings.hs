{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module TeamSettings (SettingsApi, settingsServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import Servant

data Settings = Settings { teamName :: Text, billingEmail :: Text, seatLimit :: Int }

instance FromRow Settings where
  fromRow = Settings <$> field <*> field <*> field

type SettingsApi =
       "teams" :> Capture "team" Int :> "settings" :> Get '[JSON] [Text]
  :<|> "teams" :> Capture "team" Int :> "settings" :> "reset" :> Post '[JSON] NoContent

settingsServer :: Connection -> Server SettingsApi
settingsServer conn = showSettings :<|> resetSettings
  where
    showSettings team = do
      rows <- liftIO (query conn "SELECT name, billing_email, seat_limit FROM team_settings WHERE team_id = ?" (Only team))
      pure [teamName s | s <- rows]
    resetSettings team = do
      _ <- liftIO (execute conn "UPDATE team_settings SET billing_email = '', seat_limit = 5 WHERE team_id = ?" (Only team))
      pure NoContent
