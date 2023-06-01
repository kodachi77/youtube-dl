from __future__ import unicode_literals

import re
import urllib

from .common import InfoExtractor
from .kaltura import KalturaIE
from ..utils import (
    HEADRequest,
    remove_start,
    sanitized_Request,
    smuggle_url,
    urlencode_postdata, ExtractorError,
)


class GDCVaultIE(InfoExtractor):
    _VALID_URL = r'https?://(?:www\.)?gdcvault\.com/play/(?P<id>\d+)(?:/(?P<name>[\w-]+))?'
    _NETRC_MACHINE = 'gdcvault'
    _TESTS = [
        {
            'url': 'https://www.gdcvault.com/play/1019721/Doki-Doki-Universe-Sweet-Simple',
            'md5': '7ce8388f544c88b7ac11c7ab1b593704',
            'info_dict': {
                'id': '201311826596_AWNY',
                'display_id': 'Doki-Doki-Universe-Sweet-Simple',
                'ext': 'mp4',
                'title': 'Doki-Doki Universe: Sweet, Simple and Genuine (GDC Next 10)'
            }
        },
        {
            'url': 'https://www.gdcvault.com/play/1015683/Embracing-the-Dark-Art-of',
            'info_dict': {
                'id': '201203272_1330951438328RSXR',
                'display_id': 'Embracing-the-Dark-Art-of',
                'ext': 'flv',
                'title': 'Embracing the Dark Art of Mathematical Modeling in AI'
            },
            'params': {
                'skip_download': True,  # Requires rtmpdump
            }
        },
        {
            'url': 'https://www.gdcvault.com/play/1015301/Thexder-Meets-Windows-95-or',
            'md5': 'a5eb77996ef82118afbbe8e48731b98e',
            'info_dict': {
                'id': '1015301',
                'display_id': 'Thexder-Meets-Windows-95-or',
                'ext': 'flv',
                'title': 'Thexder Meets Windows 95, or Writing Great Games in the Windows 95 Environment',
            },
            'skip': 'Requires login',
        },
        {
            'url': 'https://gdcvault.com/play/1020791/',
            'only_matching': True,
        },
        {
            # Hard-coded hostname
            'url': 'https://gdcvault.com/play/1023460/Tenacious-Design-and-The-Interface',
            'md5': 'a8efb6c31ed06ca8739294960b2dbabd',
            'info_dict': {
                'id': '840376_BQRC',
                'ext': 'mp4',
                'display_id': 'Tenacious-Design-and-The-Interface',
                'title': 'Tenacious Design and The Interface of \'Destiny\'',
            },
        },
        {
            # Multiple audios
            'url': 'https://www.gdcvault.com/play/1014631/Classic-Game-Postmortem-PAC',
            'info_dict': {
                'id': '12396_1299111843500GMPX',
                'ext': 'mp4',
                'title': 'How to Create a Good Game - From My Experience of Designing Pac-Man',
            },
            # 'params': {
            #     'skip_download': True,  # Requires rtmpdump
            #     'format': 'jp',  # The japanese audio
            # }
        },
        {
            # gdc-player.html
            'url': 'https://www.gdcvault.com/play/1435/An-American-engine-in-Tokyo',
            'info_dict': {
                'id': '9350_1238021887562UHXB',
                'display_id': 'An-American-engine-in-Tokyo',
                'ext': 'mp4',
                'title': 'An American Engine in Tokyo:/nThe collaboration of Epic Games and Square Enix/nFor THE LAST REMINANT',
            },
        },
        {
            # Kaltura Embed
            'url': 'https://www.gdcvault.com/play/1026180/Mastering-the-Apex-of-Scaling',
            'info_dict': {
                'id': '0_h1fg8j3p',
                'ext': 'mp4',
                'title': 'Mastering the Apex of Scaling Game Servers (Presented by Multiplay)',
                'timestamp': 1554401811,
                'upload_date': '20190404',
                'uploader_id': 'joe@blazestreaming.com',
            },
            'params': {
                'format': 'mp4-408',
            },
        },
        {
            # Kaltura embed, whitespace between quote and embedded URL in iframe's src
            'url': 'https://www.gdcvault.com/play/1025699',
            'info_dict': {
                'id': '0_zagynv0a',
                'ext': 'mp4',
                'title': 'Tech Toolbox',
                'upload_date': '20190408',
                'uploader_id': 'joe@blazestreaming.com',
                'timestamp': 1554764629,
            },
            'params': {
                'skip_download': True,
            },
        },
        {
            # HTML5 video
            'url': 'https://www.gdcvault.com/play/1014846/Conference-Keynote-Shigeru',
            'only_matching': True,
        },
    ]

    def _login(self, webpage_url, display_id):
        username, password = self._get_login_info()
        if username is None or password is None:
            self.report_warning('It looks like ' + webpage_url + ' requires a login. Try specifying a username and password and try again.')
            return None

        mobj = re.match(r'(?P<root_url>https?://.*?/).*', webpage_url)
        login_url = mobj.group('root_url') + 'api/login.php'
        logout_url = mobj.group('root_url') + 'logout'

        login_form = {
            'email': username,
            'password': password,
        }

        request = sanitized_Request(login_url, urlencode_postdata(login_form))
        request.add_header('Content-Type', 'application/x-www-form-urlencoded')
        self._download_webpage(request, display_id, 'Logging in')
        start_page = self._download_webpage(webpage_url, display_id, 'Getting authenticated video page')
        self._download_webpage(logout_url, display_id, 'Logging out')

        return start_page

    def _split_url(self, url):
        parsed_url = urllib.parse.urlparse(url)
        root_url = parsed_url.netloc
        params = urllib.parse.parse_qs(parsed_url.query)
        for key in params:
            params[key] = params[key][0]

        return {'root_url': root_url, 'params': params}
    def _parse_blazestreaming_media_entry(self, base_url, webpage, video_id):
        video_title = self._og_search_title(
            webpage, default=None) or self._html_search_regex(
            r'(?s)<title>(.*?)</title>', webpage, 'video title',
            default='video')

        ret = None

        iframe_url = self._search_regex(
            r'<iframe src="(.*blazestreaming\.com/\?[^"]+)".*?</iframe>',
            webpage, 'video id', default=None, fatal=False)
        if iframe_url:
            split_url = self._split_url(iframe_url)
            if not split_url['params'].get('id', None):
                raise ExtractorError("Cannot find 'id' parameter.")
            if not split_url['params'].get('videoid', None):
                split_url['params']['videoid'] = video_id

            iframe_page = self._download_webpage(iframe_url, video_id, fatal=True)
            # this function will raise an exception if JS script is not found
            self._search_regex(r'<script\s+src="(\./script_VOD.js)">', iframe_page, 'script_VOD.js', fatal=False,
                               flags=re.IGNORECASE)

            script_request = sanitized_Request("https://{0}/{1}".format(split_url['root_url'], 'script_VOD.js'))
            script_src = self._download_webpage(script_request, video_id, fatal=True)
            script_match = self._search_regex(
                    r'PLAYBACK_URL\s*=\s*[\'|"](.+)[\'|"]\s*\+\s*videoId\s*\+\s*[\'|"](.*)[\'|"]', script_src,
                    'script_VOD.js', fatal=True, flags=re.IGNORECASE, group=self.GROUP_ALL)

            url_base = script_match[0]
            url_postfix = script_match[1]
            embed_url = "{0}{1}{2}".format(url_base, split_url['params']['id'], url_postfix)

            ret = {'video_title': video_title, 'embed_url': embed_url, 'display_id': split_url['params']['videoid']}

        return ret
    @staticmethod
    def _get_cookie_value(cookies, name):
        cookie = cookies.get(name)
        if cookie:
            return cookie.value

    def _real_extract(self, url):
        res = self._extract_internal(url, False)
        if not res:
            res = self._extract_internal(url, True)
        return res

    def _extract_internal(self, url, need_login):
        video_id, name = re.match(self._VALID_URL, url).groups()
        display_id = name or video_id

        webpage_url = 'https://www.gdcvault.com/play/' + video_id
        if need_login:
            login_res = self._login(webpage_url, display_id)
            if login_res is None:
                raise ExtractorError('Could not login.')
            else:
                start_page = login_res
        else:
            start_page = self._download_webpage(webpage_url, display_id)

        direct_url = self._search_regex(
            r's1\.addVariable\("file",\s*encodeURIComponent\("(/[^"]+)"\)\);',
            start_page, 'url', default=None)
        if direct_url:
            title = self._html_search_regex(
                r'<td><strong>Session Name:?</strong></td>\s*<td>(.*?)</td>',
                start_page, 'title')
            video_url = 'https://www.gdcvault.com' + direct_url
            # resolve the url so that we can detect the correct extension
            video_url = self._request_webpage(
                HEADRequest(video_url), video_id).geturl()

            return {
                'id': video_id,
                'display_id': display_id,
                'url': video_url,
                'title': title,
            }

        embed_url = KalturaIE._extract_url(start_page)
        if embed_url:
            embed_url = smuggle_url(embed_url, {'source_url': url})
            ie_key = 'Kaltura'
        else:
            PLAYER_REGEX = r'<iframe src="(?P<xml_root>.+?)/(?:gdc-)?player.*?\.html.*?".*?</iframe>'

            xml_root = self._html_search_regex(
                PLAYER_REGEX, start_page, 'xml root', default=None)

            xml_name = self._html_search_regex(
                r'<iframe src=".*?\?xml(?:=|URL=xml/)(.+?\.xml).*?".*?</iframe>',
                start_page, 'xml filename', default=None, fatal=False)

            if xml_root and xml_name:
                embed_url = '%s/xml/%s' % (xml_root, xml_name)
                ie_key = 'DigitallySpeaking'
            else:
                res = self._parse_html5_media_entries(url, start_page, video_id)
                if res and isinstance(res, list) and len(res) > 0:
                    info = res[0]
                    info.update({
                        'title': remove_start(self._search_regex(
                            r'>Session Name:\s*<.*?>\s*<td>(.+?)</td>', start_page,
                            'title', default=None) or self._og_search_title(
                            start_page, default=None), 'GDC Vault - '),
                        'id': video_id,
                        'display_id': display_id,
                    })
                    return info
                else:
                    res = self._parse_blazestreaming_media_entry(url, start_page, video_id)
                    if res and isinstance(res, dict):
                        return {
                            'id': video_id,
                            'ext': 'mp4',
                            'display_id': res['display_id'],
                            'url': res['embed_url'],
                            'title': res['video_title'],
                            'ie_key': 'BlazeStreaming'
                        }
        if embed_url:
            return {
                '_type': 'url_transparent',
                'id': video_id,
                'display_id': display_id,
                'url': embed_url,
                'ie_key': ie_key
            }

        return None

