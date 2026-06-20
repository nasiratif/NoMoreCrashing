# NoMoreCrashing
You can use this to stop a program from crashing. Compatible with both 64 and 32-bit Windows applications. It doesn't work 100% of the time, see Limitations.

## How it works
NoMoreCrashing is an experimental program that tries to make sure the target process continues executing it's code even after an unhandled exception was encountered (a crash). It has 2 available methods of doing this:
- Inject an intruder DLL into the target process that sets a custom exception handler via `SetUnhandledExceptionFilter` that simply moves the instruction pointer ahead of the faulty instruction, then resume execution
- Attach a debugger into the target process accomplishing the same thing as the former method, but using exception debug events rather than a custom handler

## Usage
Download the latest release. If the program you want to stop from crashing is 32-bit, run the `x86` variant of NoMoreCrashing, otherwise if it's 64-bit, use the `x64` variant.
You can either inject into an already running process by selecting it's EXE in the list and clicking *Inject*, or inject at process startup via *Launch and Inject*.

Your anti-virus might trigger a false-positive. Not at all surprising given the nature of this program. :)

If that does happen, make sure to excuse this program from it.

## Demo
![Crash prevention demo](https://github.com/nasiratif/NoMoreCrashing/blob/46ab868d2105841a5296bba29e2f978edfbe40ab/Media/Demo.gif)

## Limitations
- Programs crash for a variety of different reasons so it's not always as simple as just continuing execution and ignoring the exception. Tbe results are anti-climatic at times; you might just get a freeze instead of the program continuing on smoothly
- Stack-buffer overruns/stack-overflows aren't handled. The former being a fail-fast exception so Windows skips all exception handling for it all-together, the latter clobbers up the entire stack so the exception handler can't even run (debug injection *might* workaround these problems, though I haven't tested)
- If not using debug injection, child processes won't be injected. I could probably just detour `CreateProcess` but with my method of DLL injection that's not gonna work if the CPU architectures differ
- You probably shouldn't use this on serious occasions. By continuing execution after a crash you're stepping into big undefined behavior territory as the state of the program is now effectively corrupted & unpredictable. I am not responsible for anything that goes wrong with this :) this was made just for fun!

## License
This software is distributed under the Unlicense license.

## Credits
[BeaEngine](https://github.com/BeaEngine/beaengine), utilizing it's LDE capabilities

[x64 function hooking code](https://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html)

The name of this project is a pun on another similar project, [NoMoreBugCheck](https://github.com/NSG650/NoMoreBugCheck).
