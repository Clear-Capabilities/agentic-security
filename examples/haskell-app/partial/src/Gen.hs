{-# LANGUAGE CPP #-}
{-# LANGUAGE TemplateHaskell #-}
module Gen where

import Language.Haskell.TH
import System.Process (callCommand)

#if MIN_VERSION_base(4,18,0)
import Data.List (singleton)
#endif

foreign import ccall unsafe "string.h strlen" c_strlen :: Ptr CChar -> IO CSize

-- A splice the scanner never expands, and a foreign call it never analyses.
$(return [])

-- | A real finding next to code the analysis cannot see.
runReport :: String -> IO ()
runReport name = callCommand ("report --name " ++ name)
