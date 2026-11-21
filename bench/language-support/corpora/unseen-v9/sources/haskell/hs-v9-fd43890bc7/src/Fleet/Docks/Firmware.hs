{-# LANGUAGE OverloadedStrings #-}
module Fleet.Docks.Firmware (startFirmwareWorker) where

import Network.AMQP
import System.Process.Typed (runProcess_, shell)
import qualified Data.ByteString.Lazy.Char8 as BL

startFirmwareWorker :: Channel -> IO ()
startFirmwareWorker chan = do
  _ <- declareQueue chan newQueue { queueName = "dock.firmware" }
  _ <- consumeMsgs chan "dock.firmware" Ack handleFlash
  pure ()

handleFlash :: (Message, Envelope) -> IO ()
handleFlash (msg, env) = do
  let dockId = BL.unpack (msgBody msg)
  runProcess_ (shell ("dockflash --target " ++ dockId ++ " /opt/firmware/dock.bin"))
  ackEnv env
