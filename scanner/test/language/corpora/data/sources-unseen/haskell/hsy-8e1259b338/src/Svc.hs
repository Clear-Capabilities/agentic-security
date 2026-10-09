module OrdersSvc where

import System.Log.Logger (infoM)

onIssue :: String -> String -> IO ()
onIssue user password = infoM "orders.auth" ("issued password " ++ password ++ " to " ++ user)

endpointPath :: String
endpointPath = "/orders/v0"
