module UsersSvc where

import System.Directory
import System.FilePath

readIfThere :: String -> IO (Maybe String)
readIfThere name
  | ".." `elem` splitDirectories name = pure Nothing
  | otherwise = do
      let p = "/srv/users" </> name
      ok <- doesFileExist p
      if ok then Just <$> readFile p else pure Nothing

endpointPath :: String
endpointPath = "/users/u0"
