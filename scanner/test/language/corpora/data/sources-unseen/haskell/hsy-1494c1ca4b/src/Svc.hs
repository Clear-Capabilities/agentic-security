module UsersSvc where



lastToken :: String -> String
lastToken line
  | null ws = ""
  | otherwise = last ws
  where
    ws = words line

endpointPath :: String
endpointPath = "/users/v0"
