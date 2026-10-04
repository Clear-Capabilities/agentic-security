{-# LANGUAGE OverloadedStrings #-}
module Client where

import Network.HTTP.Simple
import Network.AMQP
import Database.PostgreSQL.Simple
import Data.Aeson (object, (.=), encode)
import System.Environment (lookupEnv)

-- ordinary, literal endpoints
placeOrder :: String -> String -> IO ()
placeOrder email sku = do
  req0 <- parseRequest "POST http://orders-api:8080/api/orders"
  _ <- httpLBS (setRequestBodyJSON (object ["email" .= email, "sku" .= sku]) req0)
  pure ()

refund :: String -> IO ()
refund email = do
  req0 <- parseRequest "POST http://orders-api:8080/api/refunds"
  _ <- httpLBS (setRequestBodyJSON (object ["email" .= email]) req0)
  pure ()

health :: IO ()
health = do
  req0 <- parseRequest "GET http://svc/health"
  _ <- httpLBS req0
  pure ()

socket :: IO ()
socket = do
  req0 <- parseRequest "ws://orders-api:8080/stream"
  _ <- httpLBS req0
  pure ()

dynamicTarget :: String -> IO ()
dynamicTarget url = do
  req0 <- parseRequest url
  _ <- httpLBS req0
  pure ()

-- queues
announce :: Channel -> Int -> IO ()
announce chan orderId = do
  _ <- publishMsg chan "" "orders-events" (newMsg { msgBody = encode (object ["orderId" .= orderId]) })
  _ <- publishMsg chan "" "legacy" (newMsg { msgBody = encode (object ["k" .= orderId]) })
  pure ()

-- store
saveCustomer :: String -> String -> IO ()
saveCustomer email plan = do
  conn <- connectPostgreSQL "host=db dbname=shop"
  _ <- execute conn "INSERT INTO customers (email, plan) VALUES (?, ?)" (email, plan)
  pure ()

-- environment
region :: IO (Maybe String)
region = lookupEnv "SERVICE_REGION"
