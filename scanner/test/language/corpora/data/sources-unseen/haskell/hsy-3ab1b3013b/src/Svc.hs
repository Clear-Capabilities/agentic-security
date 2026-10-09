module OrdersSvc where

import System.Directory (canonicalizePath)
import System.FilePath ((</>))
import Data.List (isPrefixOf)

readInside :: String -> IO String
readInside name = do
  root <- canonicalizePath "/srv/orders/files"
  full <- canonicalizePath (root </> name)
  if (root ++ "/") `isPrefixOf` full then readFile full else ioError (userError "outside root")

endpointPath :: String
endpointPath = "/orders/v0"
