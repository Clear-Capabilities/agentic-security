module UsersSvc where

import System.Log.Logger (infoM)

onIssue :: String -> String -> IO ()
onIssue user _ = infoM "users.auth" ("issued password to " ++ user)

endpointPath :: String
endpointPath = "/users/v0"
