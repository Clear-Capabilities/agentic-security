{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import qualified Data.ByteString.Lazy.Char8 as BLC
import qualified Data.Map.Strict as Map
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import System.Environment (getArgs)
import System.Exit (exitFailure)

-- carrier codes accepted on the command line and the endpoint each maps to
carriers :: Map.Map String String
carriers = Map.fromList
  [ ("dhl", "https://rates.dhl.example/v2/quote")
  , ("ups", "https://quote.ups.example/api/rates")
  , ("gls", "https://api.gls.example/rates")
  ]

main :: IO ()
main = do
  args <- getArgs
  case args of
    [code] | Just endpoint <- Map.lookup code carriers -> quote endpoint
    _ -> do
      putStrLn ("usage: rate-check <" ++ unwords (Map.keys carriers) ++ ">")
      exitFailure

quote :: String -> IO ()
quote endpoint = do
  mgr <- newManager tlsManagerSettings
  request <- parseRequest endpoint
  response <- httpLbs request mgr
  BLC.putStrLn (responseBody response)
