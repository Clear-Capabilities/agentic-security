module UsersSvc where



firstWord :: [String] -> String
firstWord ws = case ws of
  (w : _) -> w
  [] -> ""

endpointPath :: String
endpointPath = "/users/v0"
