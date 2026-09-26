"""Offline HTTP regression tests; isolated state, no tunnels or backups."""
import http.client
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

import dropgate as dg


class PickupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = (dg.BASE, dg.DB_PATH, dg.SECRET_PATH, dg.FILES_DIR)
        dg.BASE = Path(self.tmp.name)
        dg.DB_PATH = dg.BASE / 'shares.json'
        dg.SECRET_PATH = dg.BASE / 'secret.key'
        dg.FILES_DIR = dg.BASE / 'files'
        dg.ensure_base()
        dg.CODE_ATTEMPTS.clear()
        self.file = dg.BASE / 'hello.txt'
        self.file.write_text('hello')
        self.download_done = threading.Event()
        done = self.download_done
        class TestHandler(dg.Handler):
            def log_message(self, *args):
                pass

            def _register_download(self, token):
                super()._register_download(token)
                done.set()
        self.server = dg.ThreadingHTTPServer(('127.0.0.1', 0), TestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        dg.BASE, dg.DB_PATH, dg.SECRET_PATH, dg.FILES_DIR = self.old
        self.tmp.cleanup()

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        conn.request(method, path, body, {'Content-Type': 'application/x-www-form-urlencoded'})
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def receive(self, code):
        return self.request('POST', '/receive', urlencode({'code': code}))

    def test_home_code_and_password(self):
        rec = dg.make_share([self.file], passphrase='secret')
        self.assertEqual(rec['pickup_code'], 'hello')  # kod = nazwa pliku bez rozszerzenia
        page = self.request('GET', '/')[2]
        self.assertIn(b'name=code', page)
        self.assertIn(b'type=text', page)  # pole ma styl z PAGE_CSS, nie domyślny przeglądarki
        self.assertIn('input[type=text]', dg.PAGE_CSS)
        code = 'HELLO.TXT'  # z rozszerzeniem i wielkimi literami też działa
        status, headers, _ = self.receive(code)
        self.assertEqual(status, 303)
        self.assertEqual(headers['Location'], '/d/' + rec['token'])
        self.assertEqual(self.request('GET', headers['Location'])[0], 401)
        self.assertEqual(self.request('GET', headers['Location'] + '/hello.txt')[0], 401)

    def test_expired_code_keeps_original_link(self):
        rec = dg.make_share([self.file])
        dg.db_update(lambda d: d['shares'][rec['token']].update(pickup_until=1))
        self.assertEqual(self.receive(rec['pickup_code'])[0], 404)
        self.assertEqual(self.request('GET', '/d/' + rec['token'])[0], 200)

    def test_expired_share_and_legacy(self):
        rec = dg.make_share([self.file], expires=-1)
        self.assertEqual(self.receive(rec['pickup_code'])[0], 404)
        legacy = dg.make_share([self.file])
        def strip(data):
            data['shares'][legacy['token']].pop('pickup_code')
            data['shares'][legacy['token']].pop('pickup_until')
        dg.db_update(strip)
        self.assertEqual(self.request('GET', '/d/' + legacy['token'])[0], 200)
        self.assertEqual(self.receive('unknown')[0], 404)

    def test_once_and_traversal(self):
        rec = dg.make_share([self.file], once=True)
        location = self.receive(rec['pickup_code'])[1]['Location']
        self.assertEqual(self.request('GET', location + '/..%2Fsecret.key')[0], 404)
        status, _, body = self.request('GET', location + '/hello.txt')
        self.assertEqual((status, body), (200, b'hello'))
        self.assertTrue(self.download_done.wait(5))
        self.assertEqual(self.receive(rec['pickup_code'])[0], 404)

    def test_filename_codes(self):
        pl = dg.BASE / 'Zdjęcie Mamy_2025.JPG'
        pl.write_text('x')
        rec = dg.make_share([pl])
        self.assertEqual(rec['pickup_code'], 'zdjecie-mamy-2025')
        for typed in ('zdjecie mamy 2025', 'Zdjęcie Mamy_2025.jpg', 'ZDJĘCIE-MAMY-2025'):
            self.assertEqual(self.receive(typed)[1].get('Location'), '/d/' + rec['token'], typed)
        # ta sama nazwa, gdy pierwszy kod jeszcze działa → sufiks
        second = dg.make_share([pl])
        self.assertEqual(second['pickup_code'], 'zdjecie-mamy-2025-2')
        self.assertEqual(self.receive('zdjecie-mamy-2025-2')[1]['Location'], '/d/' + second['token'])
        # etykieta ma pierwszeństwo przed nazwą pliku
        self.assertEqual(dg.make_share([self.file], label='Ł dla Oli')['pickup_code'], 'l-dla-oli')
        self.assertEqual(dg.code_from_name('.bashrc'), '.bashrc')
        self.assertEqual(dg.code_from_name('archiwum.tar.gz'), 'archiwum.tar')

    def test_rate_limit_and_bad_input(self):
        self.assertEqual(self.receive('żółw')[0], 404)
        for _ in range(29):
            self.assertEqual(self.receive('unknown')[0], 404)
        status, headers, _ = self.receive('unknown')
        self.assertEqual(status, 429)
        self.assertEqual(headers['Retry-After'], '60')
        self.assertEqual(self.request('POST', '/receive', 'x' * 513)[0], 400)
        dg.CODE_ATTEMPTS[:] = [t - 61 for t in dg.CODE_ATTEMPTS]
        self.assertEqual(self.receive('unknown')[0], 404)


if __name__ == '__main__':
    unittest.main()
