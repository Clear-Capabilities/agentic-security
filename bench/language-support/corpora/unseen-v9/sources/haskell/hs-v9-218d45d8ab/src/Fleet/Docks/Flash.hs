{-# LANGUAGE OverloadedStrings #-}
module Fleet.Docks.Flash (startFlashWorker) where

import Network.AMQP
import System.Process.Typed (runProcess_, proc)
import qualified Data.ByteString.Lazy.Char8 as BL

startFlashWorker :: Channel -> IO ()
startFlashWorker chan = do
  _ <- declareQueue chan newQueue { queueName = "dock.firmware" }
  _ <- consumeMsgs chan "dock.firmware" Ack handleFlash
  pure ()

handleFlash :: (Message, Envelope) -> IO ()
handleFlash (msg, env) = do
  let dockId = BL.unpack (msgBody msg)
  runProcess_ (proc "dockflash" ["--target", dockId, "/opt/firmware/dock.bin"])
  ackEnv env
