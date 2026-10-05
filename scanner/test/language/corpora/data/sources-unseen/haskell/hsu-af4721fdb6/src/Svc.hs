module UsersSvc where

import System.Process
import Data.Maybe (fromMaybe)

tools :: [(String, String)]
tools = [("zip", "zip"), ("tar", "tar")]

archive :: String -> IO ()
archive choice = case lookup choice tools of
  Just prog -> callProcess prog ["--version"]
  Nothing -> pure ()

endpointPath :: String
endpointPath = "/users/u0"
