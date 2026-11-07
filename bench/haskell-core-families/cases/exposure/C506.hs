module C506 where
import Debug.Trace

check :: Int -> Bool
check n = trace ("count=" ++ show n) (n > 0)
