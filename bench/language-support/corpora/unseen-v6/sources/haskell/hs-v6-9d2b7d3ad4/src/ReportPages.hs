{-# LANGUAGE OverloadedStrings #-}
module ReportPages (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as BLC
import Web.Scotty

main :: IO ()
main = scotty 8080 $
  get "/reports/sample" $ do
    pages <- param "pages"
    document <- liftIO (renderPages pages)
    setHeader "Content-Type" "application/pdf"
    raw document

renderPages :: Int -> IO BL.ByteString
renderPages count = BL.concat <$> mapM renderPage [1 .. count]

renderPage :: Int -> IO BL.ByteString
renderPage n = pure (BLC.pack ("%PAGE " ++ show n ++ "\n") <> BL.replicate 65536 0x20)
