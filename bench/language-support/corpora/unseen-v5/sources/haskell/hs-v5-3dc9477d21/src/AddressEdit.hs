{-# LANGUAGE OverloadedStrings, TypeFamilies #-}
module AddressEdit (postAddressEditR) where

import Control.Monad (when)
import Data.Text (Text)
import Yesod
import Yesod.Auth (requireAuthId)
import Foundation
import Model

data AddressInput = AddressInput
  { inputAddressId :: AddressId
  , inputLine1     :: Text
  , inputCity      :: Text
  , inputPostcode  :: Text
  }

addressForm :: FormInput Handler AddressInput
addressForm = AddressInput
  <$> ireq (checkMMap (pure . Right . toSqlKey) fromSqlKey intField) "address"
  <*> ireq textField "line1"
  <*> ireq textField "city"
  <*> ireq textField "postcode"

postAddressEditR :: Handler Value
postAddressEditR = do
  uid <- requireAuthId
  input <- runInputPost addressForm
  address <- runDB (get404 (inputAddressId input))
  when (addressOwner address /= uid) (permissionDenied "this address belongs to another account")
  runDB (update (inputAddressId input) [AddressLine1 =. inputLine1 input, AddressCity =. inputCity input, AddressPostcode =. inputPostcode input])
  returnJson (object ["updated" .= True])
