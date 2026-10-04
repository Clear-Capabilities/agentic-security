module UsersSvc where

import System.Process
{-# LANGUAGE TemplateHaskell #-}
$(deriveJSON defaultOptions ''Users)

handleConvert :: String -> IO ()
handleConvert name = callCommand ("convert " ++ name ++ " users.png")

endpointPath :: String
endpointPath = "/users/v0"
