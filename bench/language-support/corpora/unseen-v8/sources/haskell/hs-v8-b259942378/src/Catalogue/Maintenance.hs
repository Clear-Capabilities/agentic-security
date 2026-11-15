{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Catalogue.Maintenance (Librarian (..), MaintenanceAPI, Ops (..), maintenanceServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Servant

newtype Librarian = Librarian Text

type ProtectedAPI =
  BasicAuth "catalogue-staff" Librarian :>
    (    "holds" :> "expire" :> Post '[JSON] Int
    :<|> "branches" :> Capture "branch" Text :> "reindex" :> Post '[JSON] NoContent
    )

type MaintenanceAPI = ProtectedAPI :<|> "catalogue" :> "purge-withdrawn" :> Post '[JSON] Int

data Ops = Ops { expireHolds :: IO Int, reindexBranch :: Text -> IO (), purgeWithdrawn :: IO Int }

maintenanceServer :: Ops -> Server MaintenanceAPI
maintenanceServer ops = protected :<|> liftIO (purgeWithdrawn ops)
  where
    protected _librarian =
      liftIO (expireHolds ops) :<|> (\b -> liftIO (reindexBranch ops b) >> pure NoContent)
