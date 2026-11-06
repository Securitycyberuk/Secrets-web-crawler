import unittest
import shutil
import tempfile
import os
from pathlib import Path
from unittest.mock import patch
import cv2
import app


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        qr = cv2.QRCodeEncoder_create().encode('0x' + 'a' * 40)
        qr = cv2.resize(qr, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
        ok, image = cv2.imencode('.png', qr)
        assert ok
        cls.qr = image.tobytes()

    def run_scan(self, depth=5, robots=False):
        pages = {
            'https://example.com/': ('text/html', b'<a href="/one">next</a>'),
            'https://example.com/one': ('text/html', b'<a href="/two">next</a><img src="/wallet.png">'),
            'https://example.com/two': ('text/html', b'<p>end</p>'),
            'https://example.com/wallet.png': ('image/png', self.qr),
            'https://example.com/robots.txt': ('text/plain', b'User-agent: *\nDisallow: /one\n'),
        }
        def fetch(url, origin, max_bytes=app.MAX_BYTES):
            content_type, body = pages[url]
            return url, content_type, body
        job = {'status': 'running', 'warnings': [], 'pages': 0, 'images': 0, 'errors': 0, 'findings': []}
        app.JOBS['test'] = job
        with patch.object(app, 'safe_url', side_effect=lambda url, origin=None: url), patch.object(app, 'fetch', side_effect=fetch), patch.object(app.time, 'sleep'):
            app.crawl('test', 'https://example.com/', 100, depth, robots)
        return job

    def test_real_qr_and_recursive_crawl(self):
        job = self.run_scan()
        self.assertEqual((job['pages'], job['images'], job['errors']), (3, 1, 0))
        self.assertEqual(job['findings'][0]['type'], 'Public wallet address')
        self.assertEqual(job['findings'][0]['value'], '0x' + 'a' * 40)
        self.assertEqual(job['findings'][0]['page'], 'https://example.com/one')
        self.assertEqual(job['findings'][0]['image'], 'https://example.com/wallet.png')
        self.assertNotIn('sha256', str(job))

    def test_depth(self):
        self.assertEqual(self.run_scan(depth=0)['pages'], 1)
        self.assertEqual(self.run_scan(depth=1)['pages'], 2)
        self.assertEqual(self.run_scan(depth=None)['pages'], 3)

    def test_robots(self):
        self.assertEqual(self.run_scan(robots=True)['pages'], 1)
        self.assertEqual(self.run_scan(robots=False)['pages'], 3)

    def test_secrets_in_linked_javascript(self):
        token = 'ghp_' + 'A' * 30
        script = ('const api_key = "' + token + '";').encode()
        pages = {'https://example.com/': ('text/html', b'<script src="/app.js"></script>'),
                 'https://example.com/app.js': ('application/javascript', script)}
        def fetch(url, origin, max_bytes=app.MAX_BYTES):
            typ, data = pages[url]
            return url, typ, data
        job = {'status':'running','warnings':[],'pages':0,'images':0,'errors':0,'findings':[]}
        app.JOBS['secret-test'] = job
        with patch.object(app, 'safe_url', side_effect=lambda url, origin=None: url), patch.object(app, 'fetch', side_effect=fetch), patch.object(app.time, 'sleep'):
            app.crawl('secret-test', 'https://example.com/', None, None, False)
        found = [f for f in job['findings'] if f['type'] == 'GitHub token']
        self.assertEqual(found[0]['value'], token)
        self.assertEqual(found[0]['page'], 'https://example.com/app.js')
        self.assertEqual(found[0]['source'], 'text resource')

    def test_credential_rules(self):
        results = list(app.secret_matches('password="super-secret-123" api_key="your-api-key"'))
        self.assertEqual([v for _, v in results], ['super-secret-123'])
        self.assertEqual(results[0][0][0], 'Possible credential')

    def test_page_limit_marks_incomplete(self):
        job={'status':'running','warnings':[],'pages':0,'images':0,'errors':0,'findings':[]}
        app.JOBS['limited-test']=job
        with patch.object(app,'safe_url',side_effect=lambda url,origin=None:url), patch.object(app,'fetch',return_value=('https://example.com/','text/html',b'<a href="/next">next</a>')), patch.object(app.time,'sleep'):
            app.crawl('limited-test','https://example.com/',1,None,False)
        self.assertEqual(job['status'],'limited')
        self.assertEqual(job['queued'],1)
        self.assertTrue(job['warnings'])

    def test_unquoted_and_bearer_credentials(self):
        data = 'export CLIENT_SECRET=liveSecretValue12345\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz123456'
        found = list(app.secret_matches(data))
        self.assertIn('liveSecretValue12345', [v for _, v in found])
        self.assertIn('abcdefghijklmnopqrstuvwxyz123456', [v for _, v in found])

    @unittest.skipUnless(shutil.which('pdftotext'), 'pdftotext required')
    def test_pdf_text_extraction(self):
        stream = b'BT /F1 12 Tf 40 700 Td (password="real-secret-123") Tj ET'
        objects = [b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>', b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>', b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>', b'<< /Length ' + str(len(stream)).encode() + b' >>\nstream\n' + stream + b'\nendstream']
        pdf = bytearray(b'%PDF-1.4\n'); offsets = []
        for i, obj in enumerate(objects, 1):
            offsets.append(len(pdf)); pdf.extend(f'{i} 0 obj\n'.encode() + obj + b'\nendobj\n')
        xref = len(pdf); pdf.extend(b'xref\n0 6\n0000000000 65535 f \n')
        for offset in offsets: pdf.extend(f'{offset:010d} 00000 n \n'.encode())
        pdf.extend(f'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode())
        job={'status':'running','warnings':[],'pages':0,'images':0,'errors':0,'findings':[]}
        app.JOBS['pdf-test']=job
        with patch.object(app,'safe_url',side_effect=lambda url,origin=None:url), patch.object(app,'fetch',return_value=('https://example.com/file.pdf','application/pdf',bytes(pdf))), patch.object(app.time,'sleep'):
            app.crawl('pdf-test','https://example.com/file.pdf',None,None,False)
        self.assertEqual(job['coverage']['pdf'],1)
        self.assertEqual(job['findings'][0]['value'],'real-secret-123')
        self.assertEqual(job['findings'][0]['source'],'PDF text')

    def test_deduplicate_with_distinct_locations(self):
        job={'findings':[]}
        result=('AWS access key ID','review','identifier')
        for page in ['https://example.com/a','https://example.com/a','https://example.com/b']:
            app.add_finding(job,result,'AKIA'+'A'*16,page,'page text')
        self.assertEqual(len(job['findings']),1)
        self.assertEqual(len(job['findings'][0]['occurrences']),2)

    def test_aws_classification_and_specific_rule(self):
        value='AKIA'+'A'*16
        results=list(app.secret_matches('api_key="'+value+'"'))
        self.assertEqual(len(results),1)
        self.assertEqual(results[0][0][0], 'AWS access key ID')
        self.assertEqual(results[0][0][1], 'review')
        secret='a'*40
        results=list(app.secret_matches('AWS_SECRET_ACCESS_KEY='+secret))
        self.assertEqual([r[0][0] for r in results],['AWS secret access key'])

    def test_persistent_storage_and_interruption(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(app,'DATA_DIR',Path(temp)/'private'), patch.object(app,'DB_PATH',Path(temp)/'private'/'scans.sqlite3'), patch.dict(app.JOBS,{},clear=True):
            app.init_store()
            job={'id':'saved','status':'running','warnings':[],'findings':[{'value':'secret'}]}
            app.JOBS['saved']=job
            app.save_job(job)
            app.JOBS.clear()
            app.init_store()
            self.assertEqual(app.JOBS['saved']['status'],'interrupted')
            self.assertEqual(app.JOBS['saved']['findings'][0]['value'],'secret')
            self.assertEqual(os.stat(app.DB_PATH).st_mode & 0o777,0o600)
            self.assertEqual(os.stat(app.DATA_DIR).st_mode & 0o777,0o700)

    def test_validation_is_explicit_and_isolated(self):
        self.assertEqual(app.validate_azure_storage_format('!')['status'],'invalid format')
        self.assertEqual(app.validate_azure_storage_format('YQ==' )['status'],'not confirmed')
        self.assertEqual(app.validate_local('AKIA'+'A'*16)['status'],'format match')
        self.assertEqual(app.validate_local('0x'+'0'*40)['status'],'unchecksummed format')
        self.assertEqual(app.validate_local('0'*64)['status'],'invalid format')
        self.assertEqual(app.validate_aws('ASIA'+'A'*16,'a'*40,'')['status'],'incomplete')
        with patch.object(app.shutil,'which',return_value='/usr/bin/aws'), patch.object(app.subprocess,'run') as run:
            run.return_value.returncode=0
            run.return_value.stdout='{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/test"}'
            result=app.validate_aws('AKIA'+'A'*16,'a'*40,'')
            self.assertEqual(result['status'],'authenticated')
            kwargs=run.call_args.kwargs
            self.assertEqual(kwargs['env']['AWS_SHARED_CREDENTIALS_FILE'],'/dev/null')
            self.assertNotIn('a'*40,run.call_args.args[0])

    def test_out_of_scope_images_are_skips_not_fetch_errors(self):
        job={'status':'running','warnings':[],'pages':0,'images':0,'errors':0,'findings':[]}
        app.JOBS['skip-test']=job
        html=b'<img src="data:image/png;base64,abc"><img src="https://other.example/image.png">'
        with patch.object(app,'safe_url',side_effect=lambda url,origin=None:url), patch.object(app,'fetch',return_value=('https://example.com/','text/html',html)), patch.object(app.time,'sleep'):
            app.crawl('skip-test','https://example.com/',None,None,False)
        self.assertEqual(job['errors'],0)
        self.assertEqual(job['coverage']['external_images_skipped'],1)
        self.assertEqual(job['coverage']['non_http_images_skipped'],1)

    def test_no_successful_fetch_is_failed(self):
        job={'status':'running','warnings':[],'pages':0,'images':0,'errors':0,'findings':[]}
        app.JOBS['failed-test']=job
        with patch.object(app,'safe_url',side_effect=lambda url,origin=None:url), patch.object(app,'fetch',side_effect=ValueError('Response exceeded size limit')):
            app.crawl('failed-test','https://example.com/',None,None,False)
        self.assertEqual(job['status'],'failed')
        self.assertEqual(job['error_categories']['Response too large'],1)

    def test_azure_storage_live_mock(self):
        key=app.base64.b64encode(bytes(64)).decode()
        with patch.object(app.email.utils,'formatdate',return_value='Wed, 01 Jan 2020 00:00:00 GMT'), patch.object(app.requests,'Session') as factory:
            session=factory.return_value.__enter__.return_value
            session.get.return_value.status_code=200
            result=app.validate_azure_storage('testaccount',key)
            self.assertEqual(result['status'],'authenticated')
            args=session.get.call_args
            self.assertEqual(args.args[0],'https://testaccount.blob.core.windows.net/')
            self.assertEqual(args.kwargs['headers']['Authorization'],'SharedKey testaccount:rSDsF3BVuK7XgzAl0a9P18BWkNnFDgLCM5D96uzYB8o=')
            self.assertFalse(args.kwargs['allow_redirects'])
            session.get.return_value.status_code=403
            self.assertEqual(app.validate_azure_storage('testaccount',key)['status'],'inconclusive')
        self.assertEqual(app.validate_azure_storage('bad.example',key)['status'],'invalid input')

    def test_ethereum_balance_network_and_block(self):
        from unittest.mock import Mock
        def response(value):
            r=Mock();r.json.return_value={'jsonrpc':'2.0','result':value,'id':1};return r
        with patch.object(app,'safe_url',side_effect=lambda url:url), patch.object(app.requests,'Session') as factory:
            session=factory.return_value.__enter__.return_value
            session.post.side_effect=[response('0x1'),response('0x10'),response('0xde0b6b3a7640001')]
            result=app.ethereum_balance('0x'+'a'*40,'https://rpc.example')
            self.assertEqual(result['eth'],'1.000000000000000001')
            self.assertEqual(result['block'],16)
            self.assertEqual(session.post.call_args.kwargs['json']['params'][1],'0x10')
            session.post.side_effect=[response('0x89')]
            self.assertEqual(app.ethereum_balance('0x'+'a'*40,'https://rpc.example')['status'],'wrong network')
            self.assertEqual(app.ethereum_balance('0x'+'a'*40,'http://rpc.example')['status'],'inconclusive')

    def test_stop_before_crawl(self):
        job = {'status':'running', 'warnings':[], 'pages':0, 'images':0, 'errors':0, 'findings':[], 'cancel_requested':True}
        app.JOBS['stop-test'] = job
        with patch.object(app, 'safe_url', side_effect=lambda url, origin=None: url), patch.object(app, 'fetch') as fetch:
            app.crawl('stop-test', 'https://example.com/', None, None, False)
        self.assertEqual(job['status'], 'stopped')
        fetch.assert_not_called()
        self.assertIsNotNone(job['finished_at'])

    def test_text_detection_and_error_categories(self):
        text = 'Address: 0x' + 'a' * 40 + ' private_key=' + 'b' * 64
        kinds = [result[0] for result, value in app.text_matches(text)]
        self.assertIn('Public wallet address', kinds)
        self.assertIn('Possible private key', kinds)
        job = {'errors': 0}
        app.record_error(job, app.requests.Timeout())
        self.assertEqual(job['error_categories']['Timeout'], 1)

    def test_bitcoin_checksum_and_ambiguous_identifier(self):
        self.assertIsNone(app.classify('1hdLc9nZzTnBDcN9qJeDlJm1F9ILxxxx'))
        self.assertIsNone(app.classify('1BoatSLRHtKNngkdXEeobR76b53LETtpyU'))
        self.assertEqual(app.classify('1BoatSLRHtKNngkdXEeobR76b53LETtpyT')[0], 'Public wallet address')
        self.assertFalse(app.valid_bitcoin_address('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080'))
        self.assertTrue(app.valid_bitcoin_address('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'))

    def test_discover_azure_resources_in_content(self):
        text='https://example.blob.core.windows.net/container/file?sig=abc https://demo.vault.azure.net/'
        found=list(app.azure_resource_matches(text))
        self.assertEqual(len(found),2)
        self.assertEqual(found[0][1], 'https://example.blob.core.windows.net/container/file?sig=abc')
        self.assertEqual(found[0][0][1], 'informational')
        self.assertFalse(list(app.azure_resource_matches('https://evil.example/?next=blob.core.windows.net')))

    def test_ethereum_eip55_checks(self):
        self.assertEqual(app.keccak256(b'').hex(), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(app.ethereum_address_status('0x5AEDA56215b167893e80B4fE645BA6d5Bab767DE'), 'checksum valid')
        self.assertEqual(app.ethereum_address_status('0x5Aeda56215b167893e80B4fE645BA6d5Bab767DE'), 'checksum mismatch')
        self.assertEqual(app.ethereum_address_status('0xde709f2102306220921060314715629080e2fb77'), 'unchecksummed format')

    def test_github_new_token_not_truncated(self):
        token='ghs_12345_' + 'a'*150 + '.' + 'b'*150 + '.' + 'c'*150
        matches=list(app.secret_matches('const token="'+token+'"'))
        self.assertEqual(matches[0][1],token)
        self.assertIn('unverified',matches[0][0][2])

    def test_github_live_check_mocked(self):
        with patch.object(app.requests,'Session') as factory:
            session=factory.return_value.__enter__.return_value
            session.get.return_value.status_code=200
            session.get.return_value.json.return_value={'login':'example'}
            result=app.validate_github('ghp_'+'A'*36)
            self.assertEqual(result['status'],'authenticated')
            self.assertEqual(session.get.call_args.args[0], 'https://api.github.com/user')
            self.assertFalse(session.get.call_args.kwargs['allow_redirects'])
            session.get.return_value.status_code=403
            self.assertEqual(app.validate_github('ghs_'+'A'*36)['status'],'inconclusive')

    def test_classification_and_url_redaction(self):
        self.assertEqual(app.classify('a' * 64)[0], 'Possible private key')
        self.assertEqual(app.classify('bitcoin:example')[0], 'Payment URI')
        self.assertIsNone(app.classify('ordinary text'))
        self.assertEqual(app.sanitized('https://example.com/secret?token=value'), 'https://example.com')
        self.assertEqual(app.report_location('https://example.com/' + 'a'*64 + '?token=value'), 'https://example.com/[redacted]')


if __name__ == '__main__':
    unittest.main()
