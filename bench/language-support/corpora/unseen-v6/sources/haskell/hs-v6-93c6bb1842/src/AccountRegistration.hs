{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module AccountRegistration (app) where

import Control.Monad.IO.Class (liftIO)
import Crypto.Hash (Digest, SHA256, hash)
import Data.Aeson (FromJSON)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple
import GHC.Generics (Generic)
import Servant

data Registration = Registration { username :: Text, password :: Text, displayName :: Text }
  deriving (Show, Generic)
instance FromJSON Registration

type API = "accounts" :> ReqBody '[JSON] Registration :> PostCreated '[JSON] NoContent

digestPassword :: Text -> Text
digestPassword pw = T.pack (show (hash (TE.encodeUtf8 pw) :: Digest SHA256))

registerHandler :: Connection -> Registration -> Handler NoContent
registerHandler conn reg = do
  _ <- liftIO (execute conn
         "INSERT INTO accounts (username, display_name, password_hash) VALUES (?, ?, ?)"
         (username reg, displayName reg, digestPassword (password reg)))
  pure NoContent

app :: Connection -> Application
app conn = serve (Proxy :: Proxy API) (registerHandler conn)
