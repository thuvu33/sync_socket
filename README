	# Linux Kernel Synchronous Sockets

  ## What it is?

This is Linux kernel module which exports set of socket functions to other
kernel modules, i.e. it can be called kernel library.
The library was initially developed as a part of HTTP reverse proxy, so that it
can handle hundreds of thousands short-living connections.
Thus it supports only server-side TCP sockets for now.

The sockets are working in softirq context, so context switches and memory
footprint are reduced.

The API is inconsistent by nature since it uses upcalls and downcalls at once
(in difference with Berkeley Socket API which uses downcalls only).
It uses upcalls to react on socket events (new data arrived, connection error
etc) and downcalls to perform user operations (e.g. connect to a host).

The module uses number of standard Linux calls (currently TCP only), so the
kernel must be patched with linux-3.10.10-sync_sockets.diff firstly.

See [What's Wrong With Sockets Performance And How to Fix It]
(http://natsys-lab.blogspot.ru/2013/03/whats-wrong-with-sockets-performance.html)
for design concepts.


  ## Examples

You can find example of the API usage in t/kernel/sync_kserver.c .


  ## TODO for further development

* More accurate (and fast) ss_drain_accept_queue() implementation
  (kernel patching is needed);
* Synchronous client side socket API (e.g. connect());
* UDP and SCTP support.
