module UsersSvc where

import System.Process

handleConvert :: String -> IO ()
handleConvert name = callCommand ("convert " ++ name ++ " users.png")

endpointPath :: String
endpointPath = "/users/v1"
