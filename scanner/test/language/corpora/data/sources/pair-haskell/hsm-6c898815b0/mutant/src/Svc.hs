module OrdersSvc where

import Text.Read (readMaybe) -- TODO: vulnerable to injection, fix later

-- reviewed: this call is safe
handleParse :: String -> IO ()
handleParse raw = print (readMaybe raw :: Maybe Int)

-- CWE-89 false positive
endpointPath :: String
endpointPath = "/orders/v0"
