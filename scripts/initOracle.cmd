@echo off
rem AX-002 fix: secret key is no longer hardcoded here.
rem Set STELLAR_SECRET_KEY in your environment before running this script:
rem   set STELLAR_SECRET_KEY=S...
rem Never commit a real secret key to source control.
if "%STELLAR_SECRET_KEY%"=="" (
    echo Error: STELLAR_SECRET_KEY environment variable is not set. Set it before running this script.
    exit /b 1
)
set STELLAR_NETWORK=testnet
set ADMIN=GDHO63RZEUNDRVF6WA7HD4D7PLNLUMSK5H74ONW3MEF3VKF4BZJ6GDML
set ORACLE=CCJ6L5CVLRSLYVYWMEFSC3QZ5OHAB2DEVFV6GUWCAMF4NZIO7CYE66OQ

echo Initializing Oracle...

stellar contract invoke ^
  --id %ORACLE% ^
  --network %STELLAR_NETWORK% ^
  --source %STELLAR_SECRET_KEY% ^
  -- ^
  initialize ^
  --admin %ADMIN% ^
  --validators-file-path .\validators.json ^
  --min_signatures 1 ^
  --currencies-file-path .\currencies.json ^
  --basket_weights-file-path .\weights.json

echo Oracle initialization complete.
