"""Restricted HTTPS fetch for the legacy location lookup using system proxy settings."""
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener

ALLOWED = {'https://ipwho.is/', 'https://ipapi.co/json/', 'https://www.cloudflare.com/cdn-cgi/trace'}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('查询地址不允许重定向')


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ALLOWED:
        raise ValueError('不支持的地址')
    req = Request(sys.argv[1], headers={'Accept': 'application/json'})
    with build_opener(NoRedirect()).open(req, timeout=8) as response:
        data = response.read(65537)
        if len(data) > 65536:
            raise ValueError('响应过大')
        sys.stdout.buffer.write(data)


if __name__ == '__main__':
    main()
