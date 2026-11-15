{-# LANGUAGE OverloadedStrings #-}
module Invoices.Documents (documentRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import System.FilePath ((</>))
import Web.Spock

invoiceStore :: FilePath
invoiceStore = "/srv/invoices/rendered"

documentRoutes :: SpockM () () () ()
documentRoutes =
  get ("invoices" <//> var <//> "pdf") $ \number -> do
    pdf <- liftIO (loadRendered number)
    setHeader "Content-Type" "application/pdf"
    lazyBytes pdf

loadRendered :: String -> IO BL.ByteString
loadRendered number = BL.readFile (invoiceStore </> number ++ ".pdf")
