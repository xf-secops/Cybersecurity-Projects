{-
©AngelaMos | 2026
ConnLimit.hs
-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Aenebris.DDoS.ConnLimit
  ( ConnLimiter
  , ConnLimitConfig(..)
  , defaultConnLimitConfig
  , newConnLimiter
  , tryAcquire
  , release
  , currentCount
  , connLimitOnOpen
  , connLimitOnClose
  , defaultPerIPLimit
  , ipBytesFromSockAddr
  ) where

import Control.Concurrent.STM
  ( STM
  , TVar
  , atomically
  , modifyTVar'
  , newTVarIO
  , readTVar
  , writeTVar
  )
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS8
import Data.List (intercalate)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Network.Socket
  ( HostAddress6
  , SockAddr(..)
  , hostAddress6ToTuple
  , hostAddressToTuple
  )
import Numeric (showHex)
import Text.Printf (printf)

defaultPerIPLimit :: Int
defaultPerIPLimit = 16

data ConnLimitConfig = ConnLimitConfig
  { clcPerIPLimit :: !Int
  } deriving (Show, Eq)

defaultConnLimitConfig :: ConnLimitConfig
defaultConnLimitConfig = ConnLimitConfig { clcPerIPLimit = defaultPerIPLimit }

data ConnLimiter = ConnLimiter
  { clCounts :: TVar (Map ByteString Int)
  , clConfig :: !ConnLimitConfig
  }

newConnLimiter :: ConnLimitConfig -> IO ConnLimiter
newConnLimiter cfg = do
  tv <- newTVarIO Map.empty
  pure ConnLimiter { clCounts = tv, clConfig = cfg }

tryAcquire :: ConnLimiter -> ByteString -> STM Bool
tryAcquire ConnLimiter{..} ip = do
  m <- readTVar clCounts
  let current = Map.findWithDefault 0 ip m
      limit = clcPerIPLimit clConfig
  if current >= limit
    then pure False
    else do
      writeTVar clCounts (Map.insert ip (current + 1) m)
      pure True

release :: ConnLimiter -> ByteString -> STM ()
release ConnLimiter{..} ip =
  modifyTVar' clCounts (Map.update decrement ip)
  where
    decrement n
      | n <= 1 = Nothing
      | otherwise = Just (n - 1)

currentCount :: ConnLimiter -> ByteString -> STM Int
currentCount ConnLimiter{..} ip = do
  m <- readTVar clCounts
  pure (Map.findWithDefault 0 ip m)

connLimitOnOpen :: ConnLimiter -> SockAddr -> IO Bool
connLimitOnOpen cl sa = atomically (tryAcquire cl (ipBytesFromSockAddr sa))

connLimitOnClose :: ConnLimiter -> SockAddr -> IO ()
connLimitOnClose cl sa = atomically (release cl (ipBytesFromSockAddr sa))

ipBytesFromSockAddr :: SockAddr -> ByteString
ipBytesFromSockAddr (SockAddrInet _ ha) =
  let (a, b, c, d) = hostAddressToTuple ha
  in BS8.pack (printf "%d.%d.%d.%d" a b c d)
ipBytesFromSockAddr (SockAddrInet6 _ _ ha6 _) = v6Bytes ha6
ipBytesFromSockAddr (SockAddrUnix p) = BS8.pack ("unix:" <> p)

v6Bytes :: HostAddress6 -> ByteString
v6Bytes ha =
  let (a, b, c, d, e, f, g, h) = hostAddress6ToTuple ha
  in BS8.pack (intercalate ":" (map (`showHex` "") [a, b, c, d, e, f, g, h]))
