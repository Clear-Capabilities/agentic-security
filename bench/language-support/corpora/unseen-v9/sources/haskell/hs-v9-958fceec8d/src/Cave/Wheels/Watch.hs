{-# LANGUAGE DeriveGeneric #-}
module Cave.Wheels.Watch (watchWheels) where

import System.FSNotify
import Data.Aeson (FromJSON, decode)
import GHC.Generics (Generic)
import Control.Concurrent (threadDelay)
import Control.Monad (forever)
import System.IO (hPutStrLn, stderr)
import qualified Data.ByteString.Lazy as BL

data Wheel = Wheel { wheelId :: Int, targetHumidity :: Double } deriving Generic
instance FromJSON Wheel

watchWheels :: FilePath -> (Wheel -> IO ()) -> IO ()
watchWheels intakeDir register = withManager $ \mgr -> do
  _ <- watchDir mgr intakeDir (const True) $ \event -> do
    contents <- BL.readFile (eventPath event)
    case decode contents :: Maybe Wheel of
      Nothing -> hPutStrLn stderr ("ignoring unreadable wheel file " ++ eventPath event)
      Just wheel -> register wheel
  forever (threadDelay 1000000)
