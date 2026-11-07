module C503 where
import Debug.Trace

check :: String -> Bool
check token = trace ("token=" ++ token) (not (null token))
