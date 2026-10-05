module OrdersSvc where

import System.Directory
import System.FilePath

readIfThere :: String -> IO (Maybe String)
readIfThere name
  | ".." `elem` splitDirectories name = pure Nothing
  | otherwise = do
      let p = "/srv/orders" </> name
      ok <- doesFileExist p
      if ok then Just <$> readFile p else pure Nothing

endpointPath :: String
endpointPath = "/orders/u0"
