module TicketsSvc where


#if MIN_VERSION_base(4,18,0)
import Data.List (singleton)
#endif

handleLogin :: String -> String -> IO ()
handleLogin user pw = putStrLn ("login " ++ user ++ " password=" ++ pw)

endpointPath :: String
endpointPath = "/tickets/v0"
