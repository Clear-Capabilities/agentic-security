{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module StaffLogin (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import Data.Password.Bcrypt (Bcrypt, PasswordCheck(..), PasswordHash(..), checkPassword, mkPassword)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import GHC.Generics (Generic)
import Servant

data LoginRequest = LoginRequest { staffId :: Text, password :: Text }
  deriving (Show, Generic)
instance FromJSON LoginRequest

type API = "staff" :> "login" :> ReqBody '[JSON] LoginRequest :> Post '[JSON] Text

verifyStaff :: Connection -> LoginRequest -> IO Bool
verifyStaff conn req = do
  rows <- query conn "SELECT password_hash FROM staff WHERE staff_id = ?" (Only (staffId req))
  pure $ case rows of
    [Only stored] -> checkPassword (mkPassword (password req)) (PasswordHash stored :: PasswordHash Bcrypt) == PasswordCheckSuccess
    _ -> False

loginHandler :: Connection -> LoginRequest -> Handler Text
loginHandler conn req = do
  accepted <- liftIO (verifyStaff conn req)
  if accepted then pure "session issued" else throwError err401 { errBody = "invalid credentials" }

app :: Connection -> Application
app conn = serve (Proxy :: Proxy API) (loginHandler conn)
