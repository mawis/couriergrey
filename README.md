couriergrey
===========

Couriergrey is a C++ implementation for
[greylisting](http://en.wikipedia.org/wiki/Greylisting) for the [Courier mail
server.](http://www.courier-mta.org/)

Distribution archive can be downloaded from
[here](https://couriergrey.com/download/).

[The repository of couriergrey is now hosted on
GitHub.](https://github.com/mawis/couriergrey/)


Pros for couriergrey
--------------------

* Fast and memory saving implementation in C/C++ compiled to native code.
* Easy to install, no scripting environment required.
* Support for IPv6.


News
----

**Version 0.3.2 (2012-04-10)**

Support for gcc 4.7. Better error handling when new threads cannot be
created. Update in the database dump output.

**Version 0.3.1 (2012-01-16)**

Support for expiring old entries in the greylisting database. Please read below
for information on how this should be set up on your system.


Expiring the database
---------------------

You should create a cron job that expires your database from time to time.

This cron job should call `couriergrey` with the arguments `-e 365` to expire
entries, that are older than one year. Make sure that `couriergrey` is run as
the user, that normally accesses the database. E.g. on a standard Debian system
this is the user 'daemon'.

On a Debian system, create the file `/etc/cron.weekly/couriergrey` with
the following content:

```sh
#! /bin/bash

su -c "/usr/bin/couriergrey -e 365" daemon
```
