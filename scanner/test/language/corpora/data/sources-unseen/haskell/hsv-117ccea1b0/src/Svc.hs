module UsersSvc where

import qualified Data.ByteString as BS
import System.FilePath (takeBaseName)

load :: String -> IO BS.ByteString
load name = BS.readFile ("/srv/users/" ++ takeBaseName name ++ ".dat")

endpointPath :: String
endpointPath = "/users/v0"
