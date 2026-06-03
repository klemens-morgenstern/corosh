# corosh

A C++20 coroutine wrapper around [libssh](https://www.libssh.org/), built on
top of [Boost.Capy](https://github.com/cppalliance/capy) (coroutine task
runtime) and [Boost.Corosio](https://github.com/cppalliance/corosio)
(reactor / I/O). The library exposes the SSH transport, channels, message
plane and a from-scratch SFTP client/server as `io_task<T>`-returning
coroutines.

> [!WARNING]
> **corosh is experimental.** It is not production-ready, has not been
> security-audited, has minimal test coverage and the API is in flux. The
> primary purpose of the project today is to **demonstrate the design
> patterns required to wrap a callback-and-poll C API into a clean
> coroutine surface** on top of capy/corosio. Treat it as an executable
> piece of documentation for those two libraries.

License: LGPL-2.1-or-later (see [`LICENSE`](LICENSE) and
[`COPYING.LESSER`](COPYING.LESSER)).

---

## Table of contents

1. [What is in the box](#what-is-in-the-box)
2. [Building](#building)
3. [Background: non-blocking vs. asynchronous](#background-non-blocking-vs-asynchronous)
4. [Architecture overview](#architecture-overview)
5. [Client API](#client-api)
6. [SFTP client](#sftp-client)
7. [Server API](#server-api)
8. [SFTP server](#sftp-server)
9. [Repository layout](#repository-layout)

---

## What is in the box

| Area | Header | Implementation |
| ---- | ------ | -------------- |
| TCP listener / `ssh_bind` wrapper | [`include/corosh/acceptor.hpp`](include/corosh/acceptor.hpp) | [`src/acceptor.cpp`](src/acceptor.cpp) |
| `ssh_session` wrapper, auth, key exchange, server-side `get_message()` | [`include/corosh/session.hpp`](include/corosh/session.hpp) | [`src/session.cpp`](src/session.cpp) |
| `ssh_channel` wrapper, read / write / shell / exec / pty / subsystem requests, channel callbacks | [`include/corosh/channel.hpp`](include/corosh/channel.hpp) | [`src/channel.cpp`](src/channel.cpp) |
| Server-side `ssh_message` wrapper | [`include/corosh/message.hpp`](include/corosh/message.hpp) | [`src/message.cpp`](src/message.cpp) |
| Type-safe option wrappers (`options::host`, `options::port`, …) | [`include/corosh/options.hpp`](include/corosh/options.hpp), [`include/corosh/server_options.hpp`](include/corosh/server_options.hpp) | – |
| `std::error_category` for libssh and SFTP error codes | [`include/corosh/error.hpp`](include/corosh/error.hpp) | [`src/error.cpp`](src/error.cpp) |
| Native (non-libssh) SFTP client **and** SFTP server | [`include/corosh/sftp.hpp`](include/corosh/sftp.hpp) | [`src/sftp.cpp`](src/sftp.cpp) |
| End-to-end client demo (connect, auth, SFTP) | [`example/client.cpp`](example/client.cpp) | |
| End-to-end server demo (auth, shell, sandboxed SFTP) | [`example/server.cpp`](example/server.cpp) | |

The SFTP implementation does **not** use libssh's bundled `sftp.h` request
helpers — it speaks the wire protocol directly on top of any
`boost::capy::any_stream`. See [SFTP client](#sftp-client) and
[SFTP server](#sftp-server) below.

---

## Building

Requirements:

- A C++20 compiler (GCC 13+ or Clang 17+ have been tried).
- CMake ≥ 3.20.
- libssh ≥ 0.11 with development headers (`pkg-config --modversion libssh`).
- Boost components: `Boost::system`, `Boost::capy`, `Boost::corosio`
  (corosio is the reactor, capy is the coroutine runtime). These are not
  in upstream Boost yet — point CMake at the build that has them.

```sh
cmake -S . -B build
cmake --build build -j
```

CMake options:

| Option | Default | Effect |
| ------ | ------- | ------ |
| `COROSH_BUILD_TESTS`    | `ON` | Build the test suite in `test/` |
| `COROSH_BUILD_EXAMPLES` | `ON` | Build `example/client` and `example/server` |

See [`CMakeLists.txt`](CMakeLists.txt).

---

## Background: non-blocking vs. asynchronous

libssh — and many older C network libraries — offer a *non-blocking* mode
rather than a true *asynchronous* mode, and the distinction shapes
everything in this library.

In an **asynchronous** API you hand a function a buffer and a continuation
(callback, future, awaitable, …). The library remembers your request, the
underlying transport delivers data, and when *your* request is satisfied
the library invokes the continuation. You are woken up at most once per
logical operation, and exactly when there is something useful to report.

In a **non-blocking** API the library just refuses to block. You call
`ssh_channel_read_timeout()` or `ssh_userauth_publickey()`; if the work
can be done from already-buffered data, it returns a result, otherwise it
returns `SSH_AGAIN` (or a partial result) and leaves you to figure out
when to retry. Crucially, *the library has no concept of "your" request*
— it just processes whatever bytes are available on the SSH transport at
the moment you happen to call it. The reactor wakes up your coroutine
when the **TCP socket** is readable; libssh may then consume those bytes
into a key-re-exchange, a different channel, a global request, a
keep-alive — none of which has anything to do with the channel you were
trying to read from.

The practical consequence: **a coroutine that is awaiting "data on
channel X" is going to be resumed many times for unrelated reasons.**
Every wake-up looks the same — the socket has something to say — and the
coroutine must call back into libssh to find out whether *its* request
made any progress. If not, it has to suspend again. Three places in this
library spell that loop out:

- [`src/session.cpp`](src/session.cpp) lines 35-73 — `session::connect`.
  Drives `ssh_connect()` until it returns `SSH_OK` or `SSH_ERROR`, using
  `ssh_get_poll_flags()` to decide whether to wait for read, write or
  both on the socket.
- [`src/session.cpp`](src/session.cpp) lines 76-113 — `session::do_auth_`,
  the same loop generalized over an arbitrary `ssh_userauth_*` call that
  returns `SSH_AUTH_AGAIN` instead of `SSH_AGAIN`.
- [`src/channel.cpp`](src/channel.cpp) lines 336-411 — `channel::do_some_io_`
  / `do_io_`, the same loop again for channel read/write.

If you grep for `ssh_get_poll_flags` in this repo you will find the
same `read / write / both` switch repeated more than half a dozen times.
That is not a coincidence — it is the price of bridging a non-blocking
API into a reactor: every entry point needs its own retry loop.

There is one wrinkle worth calling out, in
[`channel.cpp`](src/channel.cpp) around line 352. Because libssh hands us
no signal of "data has arrived for *this* channel", a naive
`co_await socket->wait(read)` after `SSH_READ_PENDING` would re-fire on
every byte the peer sends for any reason — including for other channels
— and `ssh_channel_poll_timeout()` would keep returning `0`. The code
short-circuits the busy-loop by waiting on a 1 ms timer instead of the
socket. This is an honest compromise: a true async API would not need it,
but for a non-blocking library it is the right shape.

---

## Architecture overview

```
┌─────────────────────────────────────────────────────────────┐
│  your coroutine code                                        │
│      co_await session.connect(...)                          │
│      co_await channel.read_some(buf)                        │
│      co_await sftp_session.opendir("/")                     │
└──────────────────────────────┬──────────────────────────────┘
                               │ boost::capy::io_task<T>
┌──────────────────────────────┴──────────────────────────────┐
│  corosh   (this library — coroutine surface, retry loops)    │
└──────────────────────────────┬──────────────────────────────┘
            non-blocking C API │            socket wait
┌────────────────────┬─────────┴──────┐ ┌──────────────────┐
│      libssh        │  ssh_get_poll_ │ │  Boost.Corosio   │
│ (transport/crypto) │     flags()    │ │  (TCP reactor)   │
└────────────────────┴────────────────┘ └──────────────────┘
```

A few invariants follow from this layout:

- **A `corosh::session` *owns* the SSH state, but the socket is shared.**
  `session::socket_` and `channel::socket_` are both
  `std::shared_ptr<boost::corosio::tcp_socket>`
  ([`session.hpp:154`](include/corosh/session.hpp),
  [`channel.hpp:224`](include/corosh/channel.hpp)). This is required:
  open channels keep using the same socket to talk to the same peer, and
  the channel may outlive the local `session` variable in some flows
  (e.g. server-side, where a channel is spun off into its own coroutine).
  Shared ownership keeps the file descriptor alive for whoever still
  needs it.

- **`is_open()` is cheap and authoritative.**
  `session::is_open()` ([`src/session.cpp:29-33`](src/session.cpp))
  consults `ssh_get_status()` and is the natural condition for the
  server-side message loop.

- **Errors flow through `std::error_code` with a custom category.**
  libssh's integer return codes are wrapped via
  [`corosh::ssh_category()`](include/corosh/error.hpp); SFTP-level errors
  use `corosh::sftp_category()` so that `SSH_FX_EOF` and friends can
  flow through `io_result<T>` without exception machinery.

---

## Client API

### Sessions and connecting

`corosh::session` ([`session.hpp:29`](include/corosh/session.hpp))
constructs a libssh `ssh_session` and owns a `boost::corosio::tcp_socket`.
Options are typed: `session::set_option()` takes any object whose
`option()`/`data()` accessors describe a libssh option, and
[`include/corosh/options.hpp`](include/corosh/options.hpp) provides
helpers like `options::host(...)`, `options::user(...)`,
`options::log_verbosity(...)`. The same pattern is mirrored for the
server side in
[`include/corosh/server_options.hpp`](include/corosh/server_options.hpp).

Connecting is a single awaitable:

```cpp
corosh::session ses{co_await capy::this_coro::executor};
ses.set_option(corosh::options::host("localhost"));
ses.set_option(corosh::options::user("klemens"));

auto [ec] = co_await ses.connect(
    boost::corosio::endpoint(boost::corosio::ipv4_address::loopback(), 22));
```

Internally `session::connect`
([`src/session.cpp:35-73`](src/session.cpp)):

1. Opens and connects the corosio `tcp_socket` to `ep`.
2. Hands the resulting native fd back to libssh (`options::fd(...)`).
3. Calls `ssh_set_blocking(..., 0)` — from here on libssh will never
   block on the socket.
4. Enters the poll loop described in
   [non-blocking vs. asynchronous](#background-non-blocking-vs-asynchronous):
   call `ssh_connect()`, on `SSH_AGAIN` consult `ssh_get_poll_flags()`,
   await on read / write / both, retry.

The same retry shape underlies every other top-level session operation —
`handle_key_exchange()`, `listen_forward()`, `cancel_forward()` — via the
`do_op_()` helper at
[`session.cpp:222-259`](src/session.cpp).

### Authentication

User auth lives at [`session.hpp:97-108`](include/corosh/session.hpp).
Every method is an `io_task<ssh_auth_e>` and routes through
`do_auth_()` ([`src/session.cpp:76-113`](src/session.cpp)), which is the
poll loop specialized for `SSH_AUTH_AGAIN`. The example client
([`example/client.cpp:44-58`](example/client.cpp)) walks the standard
"try `none`, then `publickey_auto`, then password" sequence, consulting
`userauth_list()` to know which methods the server advertises.

`userauth_publickey_auto_get_current_identity()` is exposed for clients
that want to print which key actually authenticated.

### Channels

`corosh::channel` ([`channel.hpp:30`](include/corosh/channel.hpp)) wraps
an `ssh_channel`. The basic flow is the libssh one — `open_session()`,
optionally `request_pty()`/`request_env()`, then `request_shell()` /
`request_exec(...)` / `request_subsystem(...)` / `request_sftp()` —
each exposed as an `io_task<>`. There is also support for direct
TCP forwarding (`open_forward`, `open_forward_unix`), reverse forwarding,
and X11.

For reads and writes, `channel` exposes the full
`read_some` / `read` / `write_some` / `write` / `write_eof` family in
both single-buffer and `BufferSequence` overloads
([`channel.hpp:75-162`](include/corosh/channel.hpp)).
A nested `stderr_t` ([`channel.hpp:164-208`](include/corosh/channel.hpp))
provides the same surface for stderr, so callers can pass
`channel.std_err()` anywhere a stream is expected.

**Why `read_some` polls.** Because libssh has no per-channel readiness
signal, `channel::read_some` cannot simply `co_await
socket->wait(read)`. If it did, every byte arriving for *any* channel
would wake every channel reader, and each would discover via
`ssh_channel_poll_timeout()` that there is nothing for *it*. To avoid
spamming the logs (and burning CPU), `do_some_io_` waits on a short
timer when the only pending interest is "read"
([`src/channel.cpp:352-360`](src/channel.cpp)). Writes do not have this
problem because the socket-writable signal is per-fd, not per-channel.

### Channel callbacks (client and server)

`channel::callbacks` ([`channel.hpp:242-269`](include/corosh/channel.hpp))
is the C++-virtual-function form of `ssh_channel_callbacks_struct`.
Register an instance with `channel::add_callbacks()` and override the
events you care about (`signal`, `exit_status`, `exit_signal`,
`pty_request`, `shell_request`, `exec_request`, `env_request`,
`subsystem_request`, `close`, …). Used heavily by the server example.

---

## SFTP client

`corosh::sftp::session`
([`sftp.hpp:298-367`](include/corosh/sftp.hpp)) is a from-scratch SFTP
client built on top of `boost::capy::any_stream`. It does **not** call
into libssh's `sftp_*` helpers — the wire protocol is handled in
[`src/sftp.cpp`](src/sftp.cpp).

Two consequences:

1. **It works on any stream.** Anything that satisfies
   `boost::capy::WriteStream` and `boost::capy::ReadStream` will do — a
   `corosh::channel` is the obvious case, but you could just as well
   run SFTP over a `corosio::tcp_socket`, a pipe, or any other transport
   for testing. `sftp::init()` ([`src/sftp.cpp:233-285`](src/sftp.cpp))
   takes the stream by value and performs the version handshake itself.

2. **No dedicated reader coroutine is needed.** This is the main design
   choice worth understanding.

### Design: the response queue

A naive port of an SFTP client to coroutines tends to spawn a background
"reader" coroutine that demuxes incoming packets into per-request
futures. corosh deliberately doesn't.

The SFTP wire protocol has a strong invariant: **every request gets
exactly one response, identified by a `request_id` chosen by the
client.** That single fact makes a much smaller design viable:

`detail::response_queue` ([`sftp.hpp:48-115`](include/corosh/sftp.hpp))
holds an intrusive list of pending `response` records, each carrying a
`request_id` and a `complete()` callback. When a coroutine wants to
issue an SFTP request it:

1. Allocates a request id (`get_request_id()`).
2. Constructs a frame-allocated `response` subclass for the expected
   reply type (e.g. `ssh_fxp_handle_response`,
   `ssh_fxp_data_response`, `ssh_fxp_status_response`) and *enqueues a
   pointer to it* into an intrusive list.
3. Writes the request packet.
4. Loops: acquire the read lock, call `read_one_()`
   ([`src/sftp.cpp:306-329`](src/sftp.cpp)) which reads exactly one
   packet from the wire, dispatches it to whichever entry in the queue
   matches its `request_id`, releases the lock, and checks whether the
   response *I* was waiting for is now complete.

If another coroutine drained the packet I cared about, great — I get
woken up by the async mutex with my response already populated. If the
packet was for *someone else*, that someone else's response gets
populated and I go back to sleep. There is never a moment when nobody is
reading the stream as long as anyone is waiting for a reply.

The read-mutex / write-mutex split in `session`
([`sftp.hpp:361`](include/corosh/sftp.hpp)) keeps concurrent issuers from
interleaving partial packets on the wire while still letting any number
of them share the single read loop.

### Public surface

```cpp
auto [ec, sftp] = co_await corosh::sftp::init(std::move(channel_or_stream));

auto [ec_h, home] = co_await sftp.home_directory("klemens");
auto [ec_d, dir]  = co_await sftp.opendir(home);
while (true) {
    auto [ec, entry] = co_await dir.read();
    if (ec) break;
    std::cout << entry.name << "  " << entry.long_name << "\n";
}
auto [ec_f, f] = co_await sftp.open(home + "/foo.txt", SSH_FXF_READ, 0);
char buf[256];
auto [ec_r, n] = co_await f.read_some_at(0, capy::make_buffer(buf));
```

`file::read_some_at` / `write_some_at`
([`sftp.hpp:154-200`](include/corosh/sftp.hpp)) accept either a single
buffer or a `BufferSequence`; the multi-buffer overloads fan the work
out via `boost::capy::when_all` for free pipelining. `dir::read()`
returns an awaitable that internally batches packets — it pre-fetches a
chunk via `SSH_FXP_READDIR` and serves entries from an internal buffer
until exhausted (see `dir::read_op`,
[`sftp.hpp:238-274`](include/corosh/sftp.hpp)).

For a full walk-through see [`example/client.cpp`](example/client.cpp).

---

## Server API

The server side is the messy half, mostly because libssh's server
interface is a hybrid: some events (auth, channel-open requests) are
delivered as **callbacks**, others (the actual SSH wire messages) are
delivered as a polled **message queue**.

### Acceptor

[`corosh::acceptor`](include/corosh/acceptor.hpp) wraps `ssh_bind`. Set
options (notably `server_options::host_key(...)`), `open()`, `bind()` and
`listen()` synchronously, then `co_await acc.accept(session)` to fill in
an existing `corosh::session`. See
[`example/server.cpp:443-470`](example/server.cpp).

### The hybrid message / callback loop

A typical server session looks like this:

```cpp
corosh::session s{ex.context()};
co_await acc.accept(s);
co_await s.handle_key_exchange();

s.install_server_callbacks(std::make_unique<server_callbacks>(...));

while (s.is_open()) {
    auto [ec, msg] = co_await s.get_message();
    if (ec) break;
    switch (msg.type()) {
        case SSH_REQUEST_AUTH:    ...
        case SSH_REQUEST_SERVICE: ...
        case SSH_REQUEST_CHANNEL_OPEN: ...
    }
}
```

`session::get_message()`
([`src/session.cpp:396-430`](src/session.cpp)) is the same retry loop as
the rest of the library, calling `ssh_message_get()` and awaiting the
socket when it returns `nullptr`.

The subtle part is that **`s.get_message()` is what drives the
transport**, but some events never produce an `ssh_message` — they fire
as callbacks instead, while `get_message()` is suspended waiting for
the socket. In particular,
`session::server_callbacks::channel_open_request_session()`
([`session.hpp:179`](include/corosh/session.hpp)) is invoked
synchronously by libssh during a `get_message()` poll, and you are
expected to return an `ssh_channel` *right there*. You cannot do
asynchronous work in the callback — but you can **spawn a coroutine**
that will. The server example does exactly that:

```cpp
ssh_channel channel_open_request_session() override {
    corosh::channel c(s);
    auto h = c.native_handle();
    capy::run_async(ex, st)(wait_for_channel_request(std::move(c), w.track()));
    return h;
}
```
([`example/server.cpp:622-628`](example/server.cpp))

The callback creates a `corosh::channel` (which allocates a libssh
`ssh_channel`), hands the raw handle back to libssh synchronously, and
**fires-and-forgets** a coroutine that takes ownership of the C++
channel. That coroutine then waits — via channel callbacks — for the
client to issue `shell` / `exec` / `subsystem` / `pty` requests and
routes the channel to the appropriate handler (`echo` for shell,
`run_sftp` for an SFTP subsystem, etc.).

### `tracked_work` — keeping the session alive

Because channel coroutines are spawned independently of `ssh_main`, the
`corosh::session` is **at risk of being destroyed before all its
channels finish** — which would crash, since the channels hold pointers
back into the session.

[`example/server.cpp:533-574`](example/server.cpp) defines a tiny
RAII helper, `tracked_work`, which:

- increments a counter on construction of a `work` token,
- decrements it on destruction,
- exposes a `wait()` coroutine that suspends until the counter is zero.

Each spawned channel coroutine takes a `tracked_work::work` token by
value ([`example/server.cpp:626`](example/server.cpp)). When the main
loop wants to shut down, it requests stop via the `stop_source` and then
`co_await work.wait()` ([`example/server.cpp:684`](example/server.cpp))
before letting `session` go out of scope. The pattern generalizes — it
is essentially a tiny structured-concurrency join for fire-and-forget
coroutines.

---

## SFTP server

In contrast to the SSH server, the SFTP server is almost
anticlimactic — because **the SFTP server doesn't know anything about
channels.**

[`corosh::sftp::serve(stream, server&, worker_count)`](include/corosh/sftp.hpp)
([implementation at `src/sftp.cpp:2452-2474`](src/sftp.cpp)) takes a
`boost::capy::any_stream` and a reference to your `sftp::server`
implementation, spawns `worker_count` worker coroutines that all share a
single read and write mutex, and dispatches each incoming SFTP packet
to the appropriate `server::*` virtual.

Because the API is just "give me a stream", you can serve SFTP over
*anything*: an SSH channel (the common case), a raw TCP socket, a Unix
pipe, an in-memory stream for tests, …  The protocol parser doesn't care.

Your job is to implement [`corosh::sftp::server`
(`sftp.hpp:369-406`)](include/corosh/sftp.hpp), which is a pure-virtual
interface mapping 1-to-1 onto SFTP wire requests:

| Group | Methods |
| ----- | ------- |
| File handles | `open`, `read_at`, `write_at`, `fstat`, `fsync`, `close`, `fsetstat` |
| Directory handles | `opendir`, `readdir`, `closedir` |
| Path metadata | `stat`, `lstat`, `setstat`, `chmod`, `chown` |
| Path mutation | `unlink`, `mkdir`, `rmdir`, `rename`, `symlink`, `hardlink` |
| Path resolution | `readlink`, `canonicalize_path`, `expand_path`, `home_directory` |

[`example/server.cpp`](example/server.cpp) contains a complete sandboxed
implementation (`sftp_server`, line ~73 onward) that:

- Maintains its own handle space (`open_files` map for files,
  `dirs` map for `std::filesystem::directory_iterator`s).
- Translates between SFTP paths and local paths via `sftp_to_local` /
  `local_to_sftp` (notice the `pt.relative_path()` trick — without it,
  `root_path / "/etc/passwd"` would escape the sandbox because
  `std::filesystem::operator/` discards the left operand when the right
  one is absolute).
- Uses POSIX syscalls (`::stat`, `::ftruncate`, `::fchmod`,
  `::futimens`, …) for everything that
  `corosio::random_access_file` doesn't expose directly.

That example doubles as the recommended cookbook for writing your own
SFTP backend.

---

## Repository layout

```
corosh/
├── include/corosh/        public headers
│   ├── acceptor.hpp       TCP/ssh_bind listener
│   ├── channel.hpp        ssh_channel + channel::callbacks
│   ├── error.hpp          ssh_category, sftp_category
│   ├── message.hpp        server-side ssh_message wrapper
│   ├── options.hpp        typed wrappers for ssh_options_*
│   ├── server_options.hpp typed wrappers for ssh_bind_options_*
│   ├── session.hpp        ssh_session, server_callbacks, client_callbacks
│   └── sftp.hpp           SFTP client (session/file/dir) + server interface + serve()
│
├── src/                   matching .cpp files; all the libssh interaction lives here
│
├── example/
│   ├── client.cpp         end-to-end SSH+SFTP client
│   ├── server.cpp         end-to-end SSH+SFTP server with sandboxed SFTP backend
│   ├── host_key           generated test host key (do not reuse anywhere real)
│   └── CMakeLists.txt
│
├── test/                  test suite (work in progress)
├── API_COVERAGE.md        running notes on which libssh APIs are wrapped
├── CMakeLists.txt
└── readme.md              ← you are here
```

---

## Where to read next

If you want to understand **how to wrap a non-blocking C library**, read
[`src/session.cpp`](src/session.cpp) end-to-end — it is the smallest
file that shows every retry pattern this library uses.

If you want to understand **the SFTP design**, start at
`detail::response_queue` in
[`include/corosh/sftp.hpp`](include/corosh/sftp.hpp) and then
[`src/sftp.cpp:306-329`](src/sftp.cpp) (`read_one_`) — that is the
"no separate reader coroutine" trick in 25 lines.

If you want a **working example**, run the example server in one
terminal and the example client in another, or point your usual SSH /
SFTP client at the example server on port 8080:

```sh
./build/example/example_server &
ssh -p 8080 -o StrictHostKeyChecking=no localhost echo
sftp -P 8080 -o StrictHostKeyChecking=no localhost
```
