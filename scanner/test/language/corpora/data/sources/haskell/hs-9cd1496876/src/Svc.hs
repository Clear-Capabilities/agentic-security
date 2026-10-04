module InvoicesSvc where


class Sink a where
  emitInvoices :: a -> IO ()

handleLogin :: String -> String -> IO ()
handleLogin user pw = putStrLn ("login " ++ user ++ " password=" ++ pw)

endpointPath :: String
endpointPath = "/invoices/v0"
