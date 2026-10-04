module Types where

data Signup = Signup
  { email    :: String
  , password :: String
  , nickname :: String
  , phone    :: String
  , ssn      :: String
  }
