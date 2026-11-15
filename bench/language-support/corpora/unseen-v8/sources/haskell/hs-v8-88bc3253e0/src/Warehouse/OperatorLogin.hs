{-# LANGUAGE OverloadedStrings #-}
module Warehouse.OperatorLogin (LoginForm (..), auditLogin) where

import Data.Aeson (ToJSON (..), object, (.=))
import Data.Text (Text)
import Katip

data LoginForm = LoginForm { badge :: Text, pin :: Text, terminal :: Text }

newtype LoginEvent = LoginEvent LoginForm

instance ToJSON LoginEvent where
  toJSON (LoginEvent f) = object ["badge" .= badge f, "terminal" .= terminal f, "pin" .= ("[redacted]" :: Text)]

instance ToObject LoginEvent

instance LogItem LoginEvent where
  payloadKeys _ _ = AllKeys

auditLogin :: (KatipContext m) => LoginForm -> Bool -> m ()
auditLogin form accepted =
  katipAddContext (LoginEvent form) $
    logFM (if accepted then InfoS else WarningS) (if accepted then "operator login accepted" else "operator login rejected")
