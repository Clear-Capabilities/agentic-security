module ApiKeys (generateApiKey, shuffleBanner) where

import Crypto.Random (getRandomBytes)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as B
import System.Random (randomRIO)

generateApiKey :: IO String
generateApiKey = do
  bytes <- getRandomBytes 16 :: IO BS.ByteString
  pure (B.unpack (B16.encode bytes))

-- Cosmetic only: picks which banner the landing page shows.
shuffleBanner :: [String] -> IO String
shuffleBanner banners = (banners !!) <$> randomRIO (0, length banners - 1)
