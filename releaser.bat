@echo off
setlocal EnableDelayedExpansion
set NAME=padecer
rem LastTag=git tag -l --sort=-version:refname "v*" | head -n 1

for %%o in (darwin linux windows) do (
	echo Building %%o...
	set ext=
	
	if "%%o"=="darwin" (
		for %%a in (amd64) do (
			echo +%%a
			if "%%o"=="windows" set ext=.exe
			set GOOS=%%o
			set GOARCH=%%a
			go build -o "%NAME%-%%o-%%a!ext!"
		)
	) else (
		for %%a in (amd64 386) do (
			echo +%%a
			if "%%o"=="windows" (
				set ext=.exe
			) else (
				set ext=
			)
			set GOOS=%%o
			set GOARCH=%%a
			go build -o "%NAME%-%%o-%%a!ext!"
		)
	)
)