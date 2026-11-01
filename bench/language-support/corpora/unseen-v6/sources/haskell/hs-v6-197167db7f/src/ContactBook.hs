{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module ContactBook (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import Data.Int (Int64)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import GHC.Generics (Generic)
import Servant
import qualified Accounts
import Accounts (Account, accountId)

data ContactUpdate = ContactUpdate { contactId :: Int, line1 :: Text, city :: Text }
  deriving (Show, Generic)
instance FromJSON ContactUpdate

type API = BasicAuth "customers" Account :> "contacts" :> ReqBody '[JSON] ContactUpdate :> Put '[JSON] NoContent

updateContact :: Connection -> Account -> ContactUpdate -> IO Int64
updateContact conn account upd = execute conn "UPDATE contacts SET line1 = ?, city = ? WHERE id = ? AND account_id = ?" (line1 upd, city upd, contactId upd, accountId account)

updateHandler :: Connection -> Account -> ContactUpdate -> Handler NoContent
updateHandler conn account upd = do
  changed <- liftIO (updateContact conn account upd)
  if changed == 1 then pure NoContent else throwError err404 { errBody = "no such contact" }

app :: Connection -> Application
app conn = serveWithContext (Proxy :: Proxy API) (Accounts.basicAuthCheck :. EmptyContext) (updateHandler conn)
