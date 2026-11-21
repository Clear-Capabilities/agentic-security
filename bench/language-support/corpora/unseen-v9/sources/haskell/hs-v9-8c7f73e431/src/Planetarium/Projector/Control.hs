{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module Planetarium.Projector.Control (ControlAPI, Projector(..), controlServer) where

import Servant
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T

type ControlAPI =
       "projector" :> "status" :> Get '[JSON] T.Text
  :<|> "projector" :> "calibrate" :> Header' '[Required] "Authorization" T.Text :> Post '[JSON] NoContent
  :<|> "projector" :> "shutdown" :> Post '[JSON] NoContent

data Projector = Projector
  { lampStatus :: IO T.Text
  , runCalibration :: IO ()
  , powerOff :: IO ()
  }

controlServer :: (T.Text -> IO Bool) -> Projector -> Server ControlAPI
controlServer isOperatorToken projector = statusHandler :<|> calibrateHandler :<|> shutdownHandler
  where
    statusHandler = liftIO (lampStatus projector)
    calibrateHandler authorization = do
      allowed <- liftIO (isOperatorToken authorization)
      if allowed
        then liftIO (runCalibration projector) >> pure NoContent
        else throwError err401
    shutdownHandler = do
      liftIO (powerOff projector)
      pure NoContent
