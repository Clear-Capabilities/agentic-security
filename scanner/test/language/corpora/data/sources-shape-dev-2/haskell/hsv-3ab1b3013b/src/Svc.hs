module OrdersSvc where

import qualified Data.ByteString as BS
import System.FilePath (takeBaseName)

load :: String -> IO BS.ByteString
load name = BS.readFile ("/srv/orders/" ++ takeBaseName name ++ ".dat")

endpointPath :: String
endpointPath = "/orders/v0"
