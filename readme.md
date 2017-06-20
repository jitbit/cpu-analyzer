# Cpu analyzer
Forked from Sam Saffron's code which seems adandoned, see: http://samsaffron.com/archive/2009/11/11/Diagnosing+runaway+CPU+in+a+Net+production+application

All required dependencies are now added via NuGET, no need to link MS libraried.

Usage:

`cpu-analyzer ProcessName|PID [options]`

/S indicates how many samples to take (default:10)

/I the interval between samples in milliseconds (default:1000)

Example: `cpu-analyzer w3wp.exe /s 60 /i 500` - "Take 60 samples once every 500 milliseconds"

The tool output can be quite lengthy, so use it like this:

`cpu-analyser.exe w3wp.exe >> log.txt`

We used this tool many times to successfully find CPU "leaks" in our [helpdesk app](https://www.jitbit.com/web-helpdesk/) on production server, which has hundreds of background threads.
