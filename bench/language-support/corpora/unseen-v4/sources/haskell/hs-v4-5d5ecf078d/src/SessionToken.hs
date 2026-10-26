module SessionToken (newToken) where

import System.Random (randomRIO)
import Control.Monad (replicateM)

alphabet :: String
alphabet = ['a'..'z'] ++ ['0'..'9']

newToken :: IO String
newToken = replicateM 24 (pick <$> randomRIO (0, length alphabet - 1))
  where pick i = alphabet !! i
