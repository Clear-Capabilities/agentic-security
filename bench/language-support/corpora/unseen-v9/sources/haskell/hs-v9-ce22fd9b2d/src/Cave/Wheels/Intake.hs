{-# LANGUAGE DeriveGeneric #-}
module Cave.Wheels.Intake (watchIntake) where

import System.FSNotify
import Data.Aeson (FromJSON, decode)
import Data.Maybe (fromJust)
import GHC.Generics (Generic)
import Control.Concurrent (threadDelay)
import Control.Monad (forever)
import qualified Data.ByteString.Lazy as BL

data Wheel = Wheel { wheelId :: Int, targetHumidity :: Double } deriving Generic
instance FromJSON Wheel

watchIntake :: FilePath -> (Wheel -> IO ()) -> IO ()
watchIntake intakeDir register = withManager $ \mgr -> do
  _ <- watchDir mgr intakeDir (const True) $ \event -> do
    contents <- BL.readFile (eventPath event)
    let wheel = fromJust (decode contents) :: Wheel
    register wheel
  forever (threadDelay 1000000)
