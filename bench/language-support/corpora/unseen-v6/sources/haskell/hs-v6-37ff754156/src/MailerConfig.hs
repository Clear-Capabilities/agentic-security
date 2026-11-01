{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module MailerConfig (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import Data.IORef
import Data.Text (Text)
import GHC.Generics (Generic)
import Servant
import qualified Mailer

data MailerSettings = MailerSettings
  { smtpHost :: Text
  , smtpPort :: Int
  , smtpUser :: Text
  , smtpPassword :: Text
  , fromAddress :: Text
  } deriving (Show, Generic)
instance FromJSON MailerSettings

type API = "settings" :> "mailer" :> ReqBody '[JSON] MailerSettings :> Put '[JSON] NoContent

applySettings :: IORef MailerSettings -> MailerSettings -> IO ()
applySettings ref settings = writeIORef ref settings >> Mailer.reconnect (smtpHost settings) (smtpPort settings) (smtpUser settings) (smtpPassword settings)

settingsHandler :: IORef MailerSettings -> MailerSettings -> Handler NoContent
settingsHandler ref settings = do
  liftIO (applySettings ref settings)
  pure NoContent

app :: IORef MailerSettings -> Application
app ref = serve (Proxy :: Proxy API) (settingsHandler ref)
