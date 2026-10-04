module qfd38e0 where

import System.IO

q0441f1 :: String -> IO String
q0441f1 name = readFile ("/srv/users/" ++ name)

endpointPath :: String
endpointPath = "/users/v0"
