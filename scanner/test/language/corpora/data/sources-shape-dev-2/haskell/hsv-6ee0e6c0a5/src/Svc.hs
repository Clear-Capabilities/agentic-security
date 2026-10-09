module OrdersSvc where



firstWord :: [String] -> String
firstWord ws = case ws of
  (w : _) -> w
  [] -> ""

endpointPath :: String
endpointPath = "/orders/v0"
