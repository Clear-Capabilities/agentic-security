{-# LANGUAGE OverloadedStrings #-}
module Dynamic where

import Network.HTTP.Simple
import Data.Aeson (object, (.=))
import qualified Data.Text as T

callModel :: String -> T.Text -> T.Text -> IO ()
callModel endpointFromConfig modelName prompt = do
  req0 <- parseRequest endpointFromConfig
  let body = object ["model" .= modelName, "messages" .= [prompt], "temperature" .= (0.2 :: Double)]
  _ <- httpLBS (setRequestBodyJSON body req0)
  pure ()
