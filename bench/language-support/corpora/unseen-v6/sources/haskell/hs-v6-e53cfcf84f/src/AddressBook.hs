{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module AddressBook (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import Data.Int (Int64)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import GHC.Generics (Generic)
import Servant
import qualified Accounts
import Accounts (Account)

data AddressUpdate = AddressUpdate { addressId :: Int, line1 :: Text, city :: Text }
  deriving (Show, Generic)
instance FromJSON AddressUpdate

type API = BasicAuth "customers" Account :> "addresses" :> ReqBody '[JSON] AddressUpdate :> Put '[JSON] NoContent

updateAddress :: Connection -> AddressUpdate -> IO Int64
updateAddress conn upd = execute conn "UPDATE addresses SET line1 = ?, city = ? WHERE id = ?" (line1 upd, city upd, addressId upd)

updateHandler :: Connection -> Account -> AddressUpdate -> Handler NoContent
updateHandler conn _account upd = do
  _ <- liftIO (updateAddress conn upd)
  pure NoContent

app :: Connection -> Application
app conn = serveWithContext (Proxy :: Proxy API) (Accounts.basicAuthCheck :. EmptyContext) (updateHandler conn)
