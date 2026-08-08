@echo off
set GOARCH=amd64
echo Building...
if not exist .\build mkdir .\build
go build -o .\build\olta-proxy.exe .
