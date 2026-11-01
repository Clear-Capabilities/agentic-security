{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module MailerSettings (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import Data.IORef
import Data.Text (Text)
import GHC.Generics (Generic)
import Servant
import qualified Mailer
import qualified Operators
import Operators (Operator)

data MailerSettings = MailerSettings
  { smtpHost :: Text
  , smtpPort :: Int
  , smtpUser :: Text
  , smtpPassword :: Text
  , fromAddress :: Text
  } deriving (Show, Generic)
instance FromJSON MailerSettings

type API = BasicAuth "operators" Operator :> "settings" :> "mailer" :> ReqBody '[JSON] MailerSettings :> Put '[JSON] NoContent

applySettings :: IORef MailerSettings -> MailerSettings -> IO ()
applySettings ref settings = writeIORef ref settings >> Mailer.reconnect (smtpHost settings) (smtpPort settings) (smtpUser settings) (smtpPassword settings)

settingsHandler :: IORef MailerSettings -> Operator -> MailerSettings -> Handler NoContent
settingsHandler ref _operator settings = do
  liftIO (applySettings ref settings)
  pure NoContent

checkOperator :: BasicAuthCheck Operator
checkOperator = BasicAuthCheck $ \(BasicAuthData user pw) ->
  maybe Unauthorized Authorized <$> Operators.verify user pw

app :: IORef MailerSettings -> Application
app ref = serveWithContext (Proxy :: Proxy API) (checkOperator :. EmptyContext) (settingsHandler ref)
