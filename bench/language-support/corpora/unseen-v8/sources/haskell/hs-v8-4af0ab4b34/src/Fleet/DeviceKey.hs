module Fleet.DeviceKey (DeviceKey (..), provisionDeviceKey) where

import Data.Time.Clock.POSIX (getPOSIXTime)
import Numeric (showHex)
import System.Random (mkStdGen, randomRs)

newtype DeviceKey = DeviceKey String
  deriving (Show)

-- Each tracker unit receives a key at enrolment and signs its telemetry with it.
provisionDeviceKey :: String -> IO DeviceKey
provisionDeviceKey vin = do
  seed <- floor . (* 1000) <$> getPOSIXTime
  let gen = mkStdGen seed
      nibbles = take 64 (randomRs (0, 15 :: Int) gen)
  pure (DeviceKey (vin ++ "-" ++ concatMap (`showHex` "") nibbles))
