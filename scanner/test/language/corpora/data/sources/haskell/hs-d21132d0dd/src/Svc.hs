module UsersSvc where


#if MIN_VERSION_base(4,18,0)
import Data.List (singleton)
#endif

handleParse :: String -> IO ()
handleParse raw = print (read raw :: Int)

endpointPath :: String
endpointPath = "/users/v0"
