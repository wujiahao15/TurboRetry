import argparse
import asyncio
import logging
import os
import pickle
import ssl
import sys
import time
from collections import deque
from datetime import datetime
from typing import AsyncIterator, Deque, Dict, Optional, Tuple, cast
from urllib.parse import urlparse

import httpx
import pandas as pd
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, Headers, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.logger import QuicFileLogger
from loguru import logger as llogger

llogger.remove()
llogger.add(sys.stderr, level="INFO")
# llogger.add(sys.stderr, level="DEBUG")

logger = logging.getLogger("client")

TIME_IDXS = []
LATENCYS = []


class H3ResponseStream(httpx.AsyncByteStream):
    def __init__(self, aiterator: AsyncIterator[bytes]):
        self._aiterator = aiterator

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for part in self._aiterator:
            yield part


class H3Transport(QuicConnectionProtocol, httpx.AsyncBaseTransport):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._http = H3Connection(self._quic)
        self._read_queue: Dict[int, Deque[H3Event]] = {}
        self._read_ready: Dict[int, asyncio.Event] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        assert isinstance(request.stream, httpx.AsyncByteStream)

        stream_id = self._quic.get_next_available_stream_id()
        self._read_queue[stream_id] = deque()
        self._read_ready[stream_id] = asyncio.Event()

        # prepare request
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", request.method.encode()),
                (b":scheme", request.url.raw_scheme),
                (b":authority", request.url.netloc),
                (b":path", request.url.raw_path),
            ]
            + [
                (k.lower(), v)
                for (k, v) in request.headers.raw
                if k.lower() not in (b"connection", b"host")
            ],
        )
        async for data in request.stream:
            self._http.send_data(stream_id=stream_id, data=data, end_stream=False)
        self._http.send_data(stream_id=stream_id, data=b"", end_stream=True)

        # transmit request
        self.transmit()

        # process response
        status_code, headers, stream_ended = await self._receive_response(stream_id)

        return httpx.Response(
            status_code=status_code,
            headers=headers,
            stream=H3ResponseStream(
                self._receive_response_data(stream_id, stream_ended)
            ),
            extensions={
                "http_version": b"HTTP/3",
            },
        )

    def http_event_received(self, event: H3Event):
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._read_queue:
                self._read_queue[event.stream_id].append(event)
                self._read_ready[event.stream_id].set()

    def quic_event_received(self, event: QuicEvent):
        #  pass event to the HTTP layer
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    async def _receive_response(self, stream_id: int) -> Tuple[int, Headers, bool]:
        """
        Read the response status and headers.
        """
        stream_ended = False
        while True:
            event = await self._wait_for_http_event(stream_id)
            if isinstance(event, HeadersReceived):
                stream_ended = event.stream_ended
                break

        headers = []
        status_code = 0
        for header, value in event.headers:
            if header == b":status":
                status_code = int(value.decode())
            else:
                headers.append((header, value))
        return status_code, headers, stream_ended

    async def _receive_response_data(
        self, stream_id: int, stream_ended: bool
    ) -> AsyncIterator[bytes]:
        """
        Read the response data.
        """
        while not stream_ended:
            event = await self._wait_for_http_event(stream_id)
            if isinstance(event, DataReceived):
                stream_ended = event.stream_ended
                yield event.data
            elif isinstance(event, HeadersReceived):
                stream_ended = event.stream_ended

    async def _wait_for_http_event(self, stream_id: int) -> H3Event:
        """
        Returns the next HTTP/3 event for the given stream.
        """
        if not self._read_queue[stream_id]:
            await self._read_ready[stream_id].wait()
        event = self._read_queue[stream_id].popleft()
        if not self._read_queue[stream_id]:
            self._read_ready[stream_id].clear()
        return event


def save_session_ticket(ticket):
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)


async def send_request(
    configuration: QuicConfiguration,
    url: str,
    data: Optional[str],
    include: bool,
    output_dir: Optional[str],
) -> float:
    """
    Send a single request with a new connection and return the elapsed time.
    """
    status = "failed"
    msg = ""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port if parsed.port is not None else 443

    start_time = time.monotonic()
    try:
        async with connect(
            host,
            port,
            configuration=configuration,
            create_protocol=H3Transport,
            session_ticket_handler=save_session_ticket,
        ) as transport:
            async with httpx.AsyncClient(
                transport=cast(httpx.AsyncBaseTransport, transport),
            ) as client:
                if data is not None:
                    response = await client.post(
                        url,
                        content=data.encode(),
                        headers={"content-type": "application/x-www-form-urlencoded"},
                    )
                else:
                    response = await client.get(url)

                status = "successed"
                response.raise_for_status()
    except Exception as e:
        msg = f"{e}"
    finally:
        elapsed = time.monotonic() - start_time
        llogger.debug(f"Request {status} after {elapsed*1000:.3f} ms. {msg}")
        return elapsed


async def main(
    configuration: QuicConfiguration,
    url: str,
    data: Optional[str],
    include: bool,
    output_dir: Optional[str],
) -> None:
    global TIME_IDXS
    global LATENCYS

    req_time = time.monotonic()

    latencies = await asyncio.gather(
        *[send_request(configuration, url, data, include, output_dir) for _ in range(15)]
    )

    TIME_IDXS += [req_time] * 5
    LATENCYS += latencies

    latency_str_list = list(map(lambda x: f"{x*1000:.2f}ms", latencies))
    llogger.info(f"req finished in [{','.join(latency_str_list)}]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP/3 client")
    parser.add_argument("url", type=str, help="the URL to query (must be HTTPS)")
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from the specified file"
    )
    parser.add_argument(
        "-d", "--data", type=str, help="send the specified data in a POST request"
    )
    parser.add_argument(
        "-i",
        "--include",
        action="store_true",
        help="include the HTTP response headers in the output",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        help="write downloaded files to this directory",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-s",
        "--session-ticket",
        type=str,
        help="read and write session ticket from the specified file",
    )
    parser.add_argument(
        "--server-type",
        type=str,
        help="server type: retry or without retry",
    )
    parser.add_argument(
        "-m",
        "--measurement-path",
        type=str,
        help="path to save measurement result",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=str,
        help="timeout (seconds)",
        default=2,
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        # level=logging.DEBUG if args.verbose else logging.INFO,
        level=logging.ERROR,
    )

    if args.output_dir is not None and not os.path.isdir(args.output_dir):
        raise Exception("%s is not a directory" % args.output_dir)

    # prepare configuration
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, idle_timeout=args.timeout)
    if args.ca_certs:
        configuration.load_verify_locations(args.ca_certs)
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.quic_log:
        configuration.quic_logger = QuicFileLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")
    if args.session_ticket:
        try:
            with open(args.session_ticket, "rb") as fp:
                configuration.session_ticket = pickle.load(fp)
        except FileNotFoundError:
            pass

    if args.measurement_path is None:
        sys.exit(-1)

    tag = "normal"
    if args.server_type:
        tag = "retry"

    asyncio.run(
        main(
            configuration=configuration,
            url=args.url,
            data=args.data,
            include=args.include,
            output_dir=args.output_dir,
        )
    )
    df = pd.DataFrame({"req_time": TIME_IDXS, "latency": LATENCYS})
    df.to_parquet(args.measurement_path)
    # llogger.info(
    #     f"Records of the latency of each requests are saved to `{args.measurement_path}`"
    # )
