module OrdersSvc where

import System.Log.Logger (infoM)

onIssue :: String -> String -> IO ()
onIssue user _ = infoM "orders.auth" ("issued password to " ++ user)

endpointPath :: String
endpointPath = "/orders/v0"
