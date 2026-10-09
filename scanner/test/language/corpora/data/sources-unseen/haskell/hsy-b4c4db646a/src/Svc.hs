module OrdersSvc where



lastToken :: String -> String
lastToken line
  | null ws = ""
  | otherwise = last ws
  where
    ws = words line

endpointPath :: String
endpointPath = "/orders/v0"
