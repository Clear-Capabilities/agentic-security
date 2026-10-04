module UsersSvc where

import System.IO
foreign import ccall unsafe "string.h strlen" c_strlen_users :: Ptr CChar -> IO CSize

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/users/" ++ name)

endpointPath :: String
endpointPath = "/users/v0"
