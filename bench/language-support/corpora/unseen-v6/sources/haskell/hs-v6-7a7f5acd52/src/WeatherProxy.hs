{-# LANGUAGE OverloadedStrings #-}
module WeatherProxy (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Lazy.Encoding as TLE
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Web.Scotty

main :: IO ()
main = do
  manager <- newManager tlsManagerSettings
  base <- parseRequest "https://api.weather.example.com/v1/current"
  scotty 8080 $
    get "/weather" $ do
      city <- param "city"
      let request = setQueryString [("q", Just (BL.toStrict (TLE.encodeUtf8 city))), ("units", Just "metric")] base
      response <- liftIO (httpLbs request manager)
      setHeader "Content-Type" "application/json"
      raw (responseBody response)
