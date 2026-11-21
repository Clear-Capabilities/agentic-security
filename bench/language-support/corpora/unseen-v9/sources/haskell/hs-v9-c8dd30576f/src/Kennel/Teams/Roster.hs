{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, TemplateHaskell, QuasiQuotes, TypeFamilies, GADTs, GeneralizedNewtypeDeriving, MultiParamTypeClasses, FlexibleContexts, FlexibleInstances, DerivingStrategies, StandaloneDeriving, UndecidableInstances #-}
module Kennel.Teams.Roster (RosterAPI, rosterServer) where

import Servant
import Database.Persist
import Database.Persist.Sqlite
import Database.Persist.TH
import Control.Monad.IO.Class (liftIO)
import Data.Int (Int64)
import Data.Text (Text)

share [mkPersist sqlSettings] [persistLowerCase|
Team
    musherId Int64
    name Text
    leadDog Text
|]

type RosterAPI = "teams" :> Capture "teamId" Int64 :> Header' '[Required] "Authorization" Text :> Get '[JSON] Text

rosterServer :: ConnectionPool -> (Text -> IO (Maybe Int64)) -> Server RosterAPI
rosterServer pool musherForToken teamId authorization = do
  musher <- liftIO (musherForToken authorization)
  case musher of
    Nothing -> throwError err401
    Just _musherId -> do
      found <- liftIO (runSqlPool (get (toSqlKey teamId)) pool)
      maybe (throwError err404) (pure . teamLeadDog) found
