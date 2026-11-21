{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, DeriveGeneric #-}
module Tides.Portal.Session (SessionAPI, sessionServer) where

import Servant
import System.Random (mkStdGen, randomRs)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import GHC.Generics (Generic)
import qualified Data.Text as T

data Login = Login { station :: T.Text, password :: T.Text } deriving Generic
instance FromJSON Login

type SessionAPI = "portal" :> "session" :> ReqBody '[JSON] Login :> Post '[JSON] T.Text

sessionServer :: (T.Text -> T.Text -> IO Bool) -> (T.Text -> T.Text -> IO ()) -> Server SessionAPI
sessionServer verify remember login = do
  ok <- liftIO (verify (station login) (password login))
  if not ok
    then throwError err401
    else do
      now <- liftIO getPOSIXTime
      let sessionId = T.pack (take 32 (randomRs ('a', 'z') (mkStdGen (floor (now * 1000)))))
      liftIO (remember (station login) sessionId)
      pure sessionId
