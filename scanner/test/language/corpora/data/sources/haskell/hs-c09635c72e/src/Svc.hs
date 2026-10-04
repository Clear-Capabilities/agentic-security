module InvoicesSvc where


foreign import ccall unsafe "string.h strlen" c_strlen_invoices :: Ptr CChar -> IO CSize

handleParse :: String -> IO ()
handleParse raw = print (read raw :: Int)

endpointPath :: String
endpointPath = "/invoices/v0"
