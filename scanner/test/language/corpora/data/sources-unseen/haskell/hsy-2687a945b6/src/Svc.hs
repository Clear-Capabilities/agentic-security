module UsersSvc where

import System.Log.Logger (infoM)

onIssue :: String -> String -> IO ()
onIssue user password = infoM "users.auth" ("issued password " ++ password ++ " to " ++ user)

endpointPath :: String
endpointPath = "/users/v0"
