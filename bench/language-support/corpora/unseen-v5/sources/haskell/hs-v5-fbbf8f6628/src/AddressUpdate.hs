{-# LANGUAGE OverloadedStrings, TypeFamilies #-}
module AddressUpdate (postAddressUpdateR) where

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

postAddressUpdateR :: Handler Value
postAddressUpdateR = do
  _ <- requireAuthId
  input <- runInputPost addressForm
  runDB (update (inputAddressId input) [AddressLine1 =. inputLine1 input, AddressCity =. inputCity input, AddressPostcode =. inputPostcode input])
  returnJson (object ["updated" .= True])
