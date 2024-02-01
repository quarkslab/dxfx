<img src="https://github.com/quarkslab/dxfx/assets/56136693/9e72e4f4-fd43-45e7-be21-78708bbe98a0" height="200px" align="center" alt="DxFx Logo" />

# DxFx - The DJI Pilot DEX fixer

## Introduction

This tool provides a way to statically unpack the bytecode of the DJI Pilot
Android app, which uses a modified version of the *SecNeo* packer.

It as been tested on the following DJI Pilot versions:

- 2.5.1.17 (`642aa123437c259eea5895fe01dc4210c4a3a430842b79612074d88745f54714`)
- 2.5.1.15 (`d6f96f049bc92b01c4782e27ed94a55ab232717c7defc4c14c1059e4fa5254c8`)
- 2.5.1.10 (`860d9d75dc2b2e9426f811589b624b96000fea07cc981b15005686d3c55251d9`)

This proof of concept is used as support for the article [*DJI - The ART of obfuscation*](https://blog.quarkslab.com/dji-the-art-of-obfuscation.html) and will not be maintained thereafter.

## Getting Started

### Install

~~~bash
pip install . --user
~~~

### Usage

~~~console
$ dxfx [--output fixed_apk] apk
~~~

**Example:**

~~~console
$ dxfx com.dji.industry.pilot-v2.5.1.17.apk
~~~
