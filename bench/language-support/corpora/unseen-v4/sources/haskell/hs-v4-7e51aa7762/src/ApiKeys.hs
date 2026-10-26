module ApiKeys (generateApiKey) where

import System.Random (newStdGen, randoms)
import Numeric (showHex)
import Data.Word (Word8)

generateApiKey :: IO String
generateApiKey = do
  g <- newStdGen
  let bytes = take 16 (randoms g) :: [Word8]
  pure (concatMap (`showHex` "") bytes)
