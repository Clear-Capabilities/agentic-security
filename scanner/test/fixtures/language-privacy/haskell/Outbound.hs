{-# LANGUAGE OverloadedStrings #-}
module Outbound where

import Types
import Network.HTTP.Simple
import Network.Mail.SMTP (sendMail)
import Network.AMQP (publishMsg)
import qualified Data.ByteString.Lazy.Char8 as L

syncCrm :: Signup -> IO ()
syncCrm s = do
  req0 <- parseRequest "POST https://crm.example.test/api/contacts"
  _ <- httpLBS (setRequestBodyJSON (phone s) req0)
  pure ()

pingAnalytics :: Signup -> IO ()
pingAnalytics s = do
  req0 <- parseRequest "POST http://analytics.example.test/collect"
  _ <- httpLBS (setRequestBodyJSON (email s) req0)
  pure ()

welcome :: Signup -> IO ()
welcome s = sendMail "smtp.example.test" (L.pack (email s))

enqueue :: Signup -> IO ()
enqueue s = publishMsg (nickname s)

spill :: Signup -> IO ()
spill s = writeFile "/tmp/last-nick.txt" (nickname s)
