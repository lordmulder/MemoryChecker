---
title: Memory Checker
---


Introduction
============

**Memory Checker** is a simple memory stress-testing tool. It is useful to test the reliability of your computer's main memory (RAM) und “high” load.

Because the *Memory Checker* runs as a “normal” Windows application, it is very easy to use. There are some [limitations](#limitations) though.


Disclaimer
==========

Memory Checker puts a high stress on your computer's hardware and thus may trigger hardware problems that otherwise would have remained unnoticed.

It is possible that this will cause your system to crash. In extremely rare circumstances even permanent damage or data loss is possible!

*In **no** event will the authors of this program be liable to you for damages, including any general, special, incidental or consequential damages arising out of the use or inability to use the program; including but not limited to loss of data or data being rendered inaccurate or losses sustained by you or third parties or a failure of the program to operate with any other programs.*

By running this program on your machine, you acknowledge and agree that the use of this program is at your own risk. You have been warned &#128527;


Synopsis
========

The *Memory Checker* program is invoked as follows:

    MemoryChecker.exe [OPTIONS] [<target_memory_size>[%]] [<threads>]

**Note:** Its is *highly* recommended to close all other programs running on your machine before the Memory Checker tool is invoked!

Options
-------

The following command-line options are available:

- **`--batch`**:  
  Exit the program immediately (i.e. do **not** wait for key press) when the test has completed or failed.

- **`--continuous`**:  
  Keep the test running until either an error is detected or the test is interrupted *manually* by the user.

Exit Code
---------

Returns exit code **`0`** if and only if the test has completed without any errors. If a memory error (or other error) was detected, the exit code **`1`** is returned.


Algorithm
=========

First of all, the *Memory Checker* allocates the specified amount of memory to be tested. By default, *95%* of the computer's total physical memory will be tested.

All allocated memory pages are “locked” (pinned) in the physical memory, so that they can **not** swapped out to the disk during the test.

Once the required memory has been allocated, the actual testing begins. By default, **five** testing passed will be executed. Each pass consist of the following *two* phases:

1. Fill the entire memory with *pseudo-random* data (different in each run), using *multiple* threads in order to max out the throughput.

2. Read the entire memory, again using *multiple* threads, and verify that the retrieved data still exactly matches the data that was written originally.


Limitations
===========

Like *any* memory testing tool that runs as a program under a “normal” operating system, the Memory Checker can **not** access and test *100%* of the physical memory.

The operating system *reserves* a certain fraction of the physical memory for its own purposes. This “reserved” memory can **not** be tested.

Also, the Memory Checker does **not** allocate as much memory as possible; a certain proportion of the memory is spared, so that the system remains responsive.

This means that even though the Memory Checker *can* reveal a large number of memory problems, there is **no** hard guarantee that it will detect *any* possible problem!


Supported Platforms
===================

Memory Checker runs on any **64-Bit** version of Microsoft Windows, from *Windows XP Professional x64 Edition* (Service Pack 2) up to and including *Windows 11*.


License
=======

This work has been released under the **CC0 1.0 Universal** license.

For details, please refer to:  
<https://creativecommons.org/publicdomain/zero/1.0/legalcode>
