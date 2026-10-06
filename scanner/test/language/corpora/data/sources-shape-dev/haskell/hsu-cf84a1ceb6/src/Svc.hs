module UsersSvc where



snippet :: String -> String
snippet who = "<div class=\"users\">" <> who <> "</div>"

emit :: String -> IO ()
emit = putStrLn . snippet

endpointPath :: String
endpointPath = "/users/u0"
