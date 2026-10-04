module OrdersSvc where

import System.Process
import Data.Char (isAlphaNum)

handleUnpack :: String -> IO ()
handleUnpack name =
  if all isAlphaNum name
    then callCommand ("tar xf " ++ name ++ " -C /srv/orders")
    else pure ()

endpointPath :: String
endpointPath = "/orders/v0"
