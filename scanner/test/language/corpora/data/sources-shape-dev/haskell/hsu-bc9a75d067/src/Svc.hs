module OrdersSvc where



snippet :: String -> String
snippet who = "<div class=\"orders\">" <> who <> "</div>"

emit :: String -> IO ()
emit = putStrLn . snippet

endpointPath :: String
endpointPath = "/orders/u0"
