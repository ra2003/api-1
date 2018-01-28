import hashlib
import hmac
import json
import logging
import sys
import time
import urllib
import uuid
from random import randint

import requests
from tqdm import tqdm

from . import config
from .api_photo import configurePhoto, downloadPhoto, uploadPhoto
from .api_profile import (editProfile, getProfileData, removeProfilePicture,
                          setNameAndPhone, setPrivateAccount, setPublicAccount)
from .api_search import (fbUserSearch, searchLocation, searchTags,
                         searchUsername, searchUsers)
from .api_video import configureVideo, uploadVideo
from .prepare import delete_credentials, get_credentials

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

# The urllib library was split into other modules from Python 2 to Python 3
if sys.version_info > (3,):
    import urllib.parse


class API(object):
    def __init__(self):
        self.isLoggedIn = False
        self.LastResponse = None
        self.total_requests = 0
        self.last_login = 0
        self.last_experiments_time = 0

        self.username = None
        self.password = None
        self.user_id = None
        self.session = None

        self._token = None

        # handle logging
        self.logger = logging.getLogger('[instabot]')
        self.logger.setLevel(logging.DEBUG)
        logging.basicConfig(format='%(asctime)s %(message)s',
                            filename='instabot.log',
                            level=logging.INFO)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    @property
    def token(self):
        """
        Getting token from cookies
        """
        if not self.session or self._token:
            return None
        if self._token:
            return self._token
        cookie = self.session.cookies
        return cookie.get('csrftoken', domain='i.instagram.com')

    @token.setter
    def token(self, value):
        self._token = value

    def setUser(self, username, password):
        self.username = username
        self.password = password
        self.uuid = self.generateUUID(True)
        self.advertising_id = self.generateUUID(True)
        self.phone_id = self.generateUUID(True)
        self.device_id = self.generateDeviceId()
        self.token = None

    def login(self, username=None, password=None, force=False, proxy=None):
        if password is None:
            username, password = get_credentials(username=username)

        m = hashlib.md5()
        m.update(username.encode('utf-8') + password.encode('utf-8'))
        self.proxy = proxy
        self.device_id = self.generateDeviceId()
        self.setUser(username, password)

        if (not self.isLoggedIn or force):
            self.session = requests.Session()
            if self.proxy is not None:
                parsed = urlparse(self.proxy)
                scheme = 'http://' if not parsed.scheme else ''
                proxies = {
                    'http': scheme + self.proxy,
                    'https': scheme + self.proxy,
                }
                self.session.proxies.update(proxies)
            if (
                    self.SendRequest('si/fetch_headers/?challenge_type=signup&guid=' + self.generateUUID(False),
                                     None, True)):

                data = {'phone_id': self.generateUUID(True),
                        '_csrftoken': self.LastResponse.cookies['csrftoken'],
                        'username': self.username,
                        'guid': self.uuid,
                        'device_id': self.device_id,
                        'password': self.password,
                        'login_attempt_count': '0'}

                if self.SendRequest('accounts/login/', self.generateSignature(json.dumps(data)), True):
                    self.isLoggedIn = True
                    self.user_id = self.LastJson["logged_in_user"]["pk"]
                    self.rank_token = "%s_%s" % (self.user_id, self.uuid)
                    self.token = self.LastResponse.cookies["csrftoken"]

                    self.logger.info("Login success as %s!", self.username)
                    return True
                else:
                    self.logger.info("Login or password is incorrect.")
                    delete_credentials()
                    exit()

    def logout(self):
        if not self.isLoggedIn:
            return True
        self.isLoggedIn = not self.SendRequest('accounts/logout/')
        return not self.isLoggedIn

    def SendRequest(self, endpoint, post=None, login=False):
        if (not self.isLoggedIn and not login):
            self.logger.critical("Not logged in.")
            raise Exception("Not logged in!")

        self.session.headers.update({'Connection': 'close',
                                     'Accept': '*/*',
                                     'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                                     'Cookie2': '$Version=1',
                                     'Accept-Language': 'en-US',
                                     'User-Agent': config.USER_AGENT})
        try:
            self.total_requests += 1
            if post is not None:  # POST
                response = self.session.post(
                    config.API_URL + endpoint, data=post)
            else:  # GET
                response = self.session.get(
                    config.API_URL + endpoint)
        except Exception as e:
            self.logger.warning(str(e))
            return False

        if response.status_code == 200:
            self.LastResponse = response
            self.LastJson = json.loads(response.text)
            return True
        else:
            self.logger.error("Request return %s error!", str(response.status_code))
            if response.status_code == 429:
                sleep_minutes = 5
                self.logger.warning("That means 'too many requests'. "
                                    "I'll go to sleep for %d minutes.", sleep_minutes)
                time.sleep(sleep_minutes * 60)
            elif response.status_code == 400:
                response_data = json.loads(response.text)
                self.logger.info("Instagram error message: %s", response_data.get('message'))
                if response_data.get('error_type'):
                    self.logger.info('Error type: %s', response_data.get('error_type'))

            # for debugging
            try:
                self.LastResponse = response
                self.LastJson = json.loads(response.text)
            except Exception:
                pass
            return False

    def syncFeatures(self):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            'id': self.user_id,
            '_csrftoken': self.token,
            'experiments': config.EXPERIMENTS
        })
        return self.SendRequest('qe/sync/', self.generateSignature(data))

    def send_pre_login_flow(self):
        self.sync_device_features(True)
        self.read_msisdn_header()
        self.log_attribution()

    def read_msisdn_header(self, subno_key=None):
        data = {
            'device_id': self.uuid,
            '_csrftoken': self.token
        }

        if subno_key:
            data['subno_key'] = subno_key
        return self.SendRequest('accounts/read_msisdn_header/', data, True)

    def log_attribution(self):
        data = {
            'adid': self.advertising_id
        }
        return self.SendRequest('attribution/log_attribution/', data, True)

    def login2(self, username, password, force_login=False, refresh_interval=1800):
        # Switch the currently active user/pass if the details are different
        if self.username != username or self.password != password:
            self.setUser(username, password)

        # Perform a full relogin if necessary
        if force_login or not self.isLoggedIn:
            self.session = requests.Session()
            self.send_pre_login_flow()

            login_data = {
                'phone_id': self.phone_id,
                '_csrftoken': self.token,
                'username': self.username,
                'adid': self.advertising_id,
                'guid': self.uuid,
                'device_id': self.device_id,
                'password': self.password,
                'login_attempt_count': 0
            }

            response = self.SendRequest('accounts/login/', login_data)

            # TODO: Check on two factor requires
            self.update_login_state(self.LastJson)
            self.send_login_flow(True, refresh_interval)

            return response

    def send_login_flow(self, just_logged_in, app_refresh_interval=1800):
        if not isinstance(app_refresh_interval, int) or app_refresh_interval < 0:
            raise Exception("Instagram's app state refresh interval must be a positive integer.")
        if app_refresh_interval > 21600:
            raise Exception("Instagram's app state refresh interval is NOT allowed to be higher than 6 hours, and the lower the better!")

        if just_logged_in:
            self.opening_app_activity()
        else:
            # Act like a real logged in app client refreshing its news timeline.
            # This also lets us detect if we're still logged in with a valid session.
            self.getTimelineFeed()
            if self.LastResponse.status_code != 200:
                self.login2(self.username, self.password, True, app_refresh_interval)

            last_login = self.last_login
            if not last_login or time.time() - last_login > app_refresh_interval:
                self.last_login = time.time()
                # Generate and save new application session ID
                self.session_id = self.generateUUID(True)
                self.opening_app_activity()

            last_experiments_time = self.last_experiments_time

            if not isinstance(last_experiments_time, int) or time.time - last_experiments_time > config.EXPERIMENTS_REFRESH:
                self.syncFeatures()
                self.sync_device_features()

            # TODO: Save cookie jar

    def sync_device_features(self, prelogin=False):
        data = {
            'id': self.uuid,
            'experiments': config.LOGIN_EXPERIMENTS
        }
        if not prelogin:
            data['_uuid'] = self.uuid,
            data['_uid'] = self.user_id,
            data['_csrftoken'] = self.token

        return self.SendRequest('qe/sync/', data, True)

    def opening_app_activity(self):
        self.autoCompleteUserList()
        self.getTimelineFeed()
        self.syncFeatures()
        self.getv2Inbox()
        self.getRecentActivity()

    def update_login_state(self, response):
        if not response.get('status') != 'ok' and response.get('logged_in_user'):
            self.logger.error('Invalid login response provided to update_login_state()')

        self.isLoggedIn = True
        self.user_id = response.get('logged_in_user').get('pk')
        self.rank_token = "{0}_{1}".format(self.user_id, self.uuid)
        self.last_login = time.time()

    def autoCompleteUserList(self):
        return self.SendRequest('friendships/autocomplete_user_list/')

    def getTimelineFeed(self):
        """ Returns 8 medias from timeline feed of logged user """
        return self.SendRequest('feed/timeline/')

    def megaphoneLog(self):
        return self.SendRequest('megaphone/log/')

    def expose(self):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            'id': self.user_id,
            '_csrftoken': self.token,
            'experiment': 'ig_android_profile_contextual_feed'
        })
        return self.SendRequest('qe/expose/', self.generateSignature(data))

    def uploadPhoto(self, photo, caption=None, upload_id=None):
        return uploadPhoto(self, photo, caption, upload_id)

    def downloadPhoto(self, media_id, filename, media=False, path='photos/'):
        return downloadPhoto(self, media_id, filename, media, path)

    def configurePhoto(self, upload_id, photo, caption=''):
        return configurePhoto(self, upload_id, photo, caption)

    def uploadVideo(self, photo, caption=None, upload_id=None):
        return uploadVideo(self, photo, caption, upload_id)

    def configureVideo(self, upload_id, video, thumbnail, caption=''):
        return configureVideo(self, upload_id, video, thumbnail, caption)

    def editMedia(self, mediaId, captionText=''):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            '_csrftoken': self.token,
            'caption_text': captionText
        })
        return self.SendRequest('media/' + str(mediaId) + '/edit_media/', self.generateSignature(data))

    def removeSelftag(self, mediaId):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            '_csrftoken': self.token
        })
        return self.SendRequest('media/' + str(mediaId) + '/remove/', self.generateSignature(data))

    def mediaInfo(self, mediaId):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            '_csrftoken': self.token,
            'media_id': mediaId
        })
        return self.SendRequest('media/' + str(mediaId) + '/info/', self.generateSignature(data))

    def archiveMedia(self, media, undo=False):
        action = 'only_me' if not undo else 'undo_only_me'
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            '_csrftoken': self.token,
            'media_id': media['id']
        })
        return self.SendRequest('media/' + str(media['id']) + '/' + str(action) + '/?media_type=' +
                                str(media['media_type']), self.generateSignature(data))

    def deleteMedia(self, media):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            '_csrftoken': self.token,
            'media_id': media.get('id')
        })
        return self.SendRequest('media/' + str(media.get('id')) + '/delete/', self.generateSignature(data))

    def changePassword(self, newPassword):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            '_csrftoken': self.token,
            'old_password': self.password,
            'new_password1': newPassword,
            'new_password2': newPassword
        })
        return self.SendRequest('accounts/change_password/', self.generateSignature(data))

    def explore(self):
        return self.SendRequest('discover/explore/')

    def comment(self, mediaId, commentText):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            '_csrftoken': self.token,
            'comment_text': commentText
        })
        return self.SendRequest('media/' + str(mediaId) + '/comment/', self.generateSignature(data))

    def deleteComment(self, mediaId, commentId):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            '_csrftoken': self.token
        })
        return self.SendRequest('media/' + str(mediaId) + '/comment/' + str(commentId) + '/delete/',
                                self.generateSignature(data))

    def removeProfilePicture(self):
        return removeProfilePicture(self)

    def setPrivateAccount(self):
        return setPrivateAccount(self)

    def setPublicAccount(self):
        return setPublicAccount(self)

    def getProfileData(self):
        return getProfileData(self)

    def editProfile(self, url, phone, first_name, biography, email, gender):
        return editProfile(self, url, phone, first_name, biography, email, gender)

    def getUsernameInfo(self, usernameId):
        return self.SendRequest('users/' + str(usernameId) + '/info/')

    def getSelfUsernameInfo(self):
        return self.getUsernameInfo(self.user_id)

    def getRecentActivity(self):
        activity = self.SendRequest('news/inbox/?')
        return activity

    def getFollowingRecentActivity(self):
        activity = self.SendRequest('news/?')
        return activity

    def getv2Inbox(self):
        inbox = self.SendRequest('direct_v2/inbox/?')
        return inbox

    def getUserTags(self, usernameId):
        tags = self.SendRequest('usertags/' + str(usernameId) +
                                '/feed/?rank_token=' + str(self.rank_token) + '&ranked_content=true&')
        return tags

    def getSelfUserTags(self):
        return self.getUserTags(self.user_id)

    def tagFeed(self, tag):
        userFeed = self.SendRequest(
            'feed/tag/' + str(tag) + '/?rank_token=' + str(self.rank_token) + '&ranked_content=true&')
        return userFeed

    def getMediaLikers(self, media_id):
        likers = self.SendRequest('media/' + str(media_id) + '/likers/?')
        return likers

    def getGeoMedia(self, usernameId):
        locations = self.SendRequest('maps/user/' + str(usernameId) + '/')
        return locations

    def getSelfGeoMedia(self):
        return self.getGeoMedia(self.user_id)

    def fbUserSearch(self, query):
        return fbUserSearch(self, query)

    def searchUsers(self, query):
        return searchUsers(self, query)

    def searchUsername(self, username):
        return searchUsername(self, username)

    def searchTags(self, query):
        return searchTags(self, query)

    def searchLocation(self, query='', lat=None, lng=None):
        return searchLocation(self, query, lat, lng)

    def syncFromAdressBook(self, contacts):
        return self.SendRequest('address_book/link/?include=extra_display_name,thumbnails',
                                "contacts=" + json.dumps(contacts))

    def getTimeline(self):
        query = self.SendRequest(
            'feed/timeline/?rank_token=' + str(self.rank_token) + '&ranked_content=true&')
        return query

    def getArchiveFeed(self):
        query = self.SendRequest(
            'feed/only_me_feed/?rank_token=' + str(self.rank_token) + '&ranked_content=true&')
        return query

    def getUserFeed(self, usernameId, maxid='', minTimestamp=None):
        query = self.SendRequest(
            'feed/user/' + str(usernameId) + '/?max_id=' + str(maxid) + '&min_timestamp=' + str(minTimestamp) +
            '&rank_token=' + str(self.rank_token) + '&ranked_content=true')
        return query

    def getSelfUserFeed(self, maxid='', minTimestamp=None):
        return self.getUserFeed(self.user_id, maxid, minTimestamp)

    def getHashtagFeed(self, hashtagString, maxid=''):
        return self.SendRequest('feed/tag/' + hashtagString + '/?max_id=' + str(
            maxid) + '&rank_token=' + self.rank_token + '&ranked_content=true&')

    def getLocationFeed(self, locationId, maxid=''):
        return self.SendRequest('feed/location/' + str(locationId) + '/?max_id=' + str(
            maxid) + '&rank_token=' + self.rank_token + '&ranked_content=true&')

    def getPopularFeed(self):
        popularFeed = self.SendRequest(
            'feed/popular/?people_teaser_supported=1&rank_token=' + str(self.rank_token) + '&ranked_content=true&')
        return popularFeed

    def getUserFollowings(self, usernameId, maxid=''):
        return self.SendRequest('friendships/' + str(usernameId) + '/following/?max_id=' + str(maxid) +
                                '&ig_sig_key_version=' + config.SIG_KEY_VERSION + '&rank_token=' + self.rank_token)

    def getSelfUsersFollowing(self):
        return self.getUserFollowings(self.user_id)

    def getUserFollowers(self, usernameId, maxid=''):
        if maxid == '':
            return self.SendRequest('friendships/' + str(usernameId) + '/followers/?rank_token=' + self.rank_token)
        else:
            return self.SendRequest(
                'friendships/' + str(usernameId) + '/followers/?rank_token=' + self.rank_token + '&max_id=' + str(
                    maxid))

    def getSelfUserFollowers(self):
        return self.getUserFollowers(self.user_id)

    def like(self, mediaId):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            '_csrftoken': self.token,
            'media_id': mediaId
        })
        return self.SendRequest('media/' + str(mediaId) + '/like/', self.generateSignature(data))

    def unlike(self, mediaId):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            '_csrftoken': self.token,
            'media_id': mediaId
        })
        return self.SendRequest('media/' + str(mediaId) + '/unlike/', self.generateSignature(data))

    def getMediaComments(self, mediaId):
        return self.SendRequest('media/' + str(mediaId) + '/comments/?')

    def setNameAndPhone(self, name='', phone=''):
        return setNameAndPhone(self, name, phone)

    def getDirectShare(self):
        return self.SendRequest('direct_share/inbox/?')

    def follow(self, userId):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            'user_id': userId,
            '_csrftoken': self.token
        })
        return self.SendRequest('friendships/create/' + str(userId) + '/', self.generateSignature(data))

    def unfollow(self, userId):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            'user_id': userId,
            '_csrftoken': self.token
        })
        return self.SendRequest('friendships/destroy/' + str(userId) + '/', self.generateSignature(data))

    def block(self, userId):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            'user_id': userId,
            '_csrftoken': self.token
        })
        return self.SendRequest('friendships/block/' + str(userId) + '/', self.generateSignature(data))

    def unblock(self, userId):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            'user_id': userId,
            '_csrftoken': self.token
        })
        return self.SendRequest('friendships/unblock/' + str(userId) + '/', self.generateSignature(data))

    def userFriendship(self, userId):
        data = json.dumps({
            '_uuid': self.uuid,
            '_uid': self.user_id,
            'user_id': userId,
            '_csrftoken': self.token
        })
        return self.SendRequest('friendships/show/' + str(userId) + '/', self.generateSignature(data))

    def _prepareRecipients(self, users, threadId=None, useQuotes=False):
        if not isinstance(users, list):
            print('Users must be an list')
            return False
        result = {'users': '[[{}]]'.format(','.join(users))}
        if threadId:
            result['thread'] = '["{}"]'.format(threadId) if useQuotes else '[{}]'.format(threadId)
        return result

    def sendDirectItem(self, itemType, users, **options):
        data = {
            '_uuid': self.uuid,
            '_uid': self.user_id,
            '_csrftoken': self.token,
            'client_context': self.generateUUID(True),
            'action': 'send_item'
        }
        url = ''
        if itemType == 'links':
            data['link_text'] = options.get('text')
            data['link_urls'] = json.dumps(options.get('urls'))
            url = 'direct_v2/threads/broadcast/link/'
        elif itemType == 'message':
            data['text'] = options.get('text', '')
            url = 'direct_v2/threads/broadcast/text/'
        elif itemType == 'media_share':
            data['media_type'] = options.get('media_type', 'photo')
            data['text'] = options.get('text', '')
            data['media_id'] = options.get('media_id', '')
            url = 'direct_v2/threads/broadcast/media_share/'
        elif itemType == 'like':
            url = 'direct_v2/threads/broadcast/like/'
        elif itemType == 'hashtag':
            url = 'direct_v2/threads/broadcast/hashtag/'
            data['text'] = options.get('text', '')
            data['hashtag'] = options.get('hashtag', '')
        elif itemType == 'profile':
            url = 'direct_v2/threads/broadcast/profile/'
            data['profile_user_id'] = options.get('profile_user_id')
            data['text'] = options.get('text', '')
        recipients = self._prepareRecipients(users, threadId=options.get('thread'), useQuotes=False)
        if not recipients:
            return False
        data['recipient_users'] = recipients.get('users')
        if recipients.get('thread'):
            data['thread_ids'] = recipients.get('thread')
        return self.SendRequest(url, data)

    def generateSignature(self, data):
        try:
            parsedData = urllib.parse.quote(data)
        except AttributeError:
            parsedData = urllib.quote(data)

        return 'ig_sig_key_version=' + config.SIG_KEY_VERSION + '&signed_body=' + hmac.new(
            config.IG_SIG_KEY.encode('utf-8'), data.encode('utf-8'), hashlib.sha256).hexdigest() + '.' + parsedData

    def generateDeviceId(self):
        import time
        seed = str(round(time.time() * 1000000))
        m = hashlib.md5(seed.encode('utf-8'))
        return 'android-' + m.hexdigest()[:16]

    def generateUUID(self, uuid_type):
        generated_uuid = str(uuid.uuid4())
        if (uuid_type):
            return generated_uuid
        else:
            return generated_uuid.replace('-', '')

    def getLikedMedia(self, maxid=''):
        return self.SendRequest('feed/liked/?max_id=' + str(maxid))

    def getTotalFollowers(self, usernameId, amount=None):
        sleep_track = 0
        followers = []
        next_max_id = ''
        self.getUsernameInfo(usernameId)
        if "user" in self.LastJson:
            if amount:
                total_followers = amount
            else:
                total_followers = self.LastJson["user"]['follower_count']
            if total_followers > 200000:
                print("Consider temporarily saving the result of this big operation. This will take a while.\n")
        else:
            return False
        with tqdm(total=total_followers, desc="Getting followers", leave=False) as pbar:
            while True:
                self.getUserFollowers(usernameId, next_max_id)
                temp = self.LastJson
                try:
                    pbar.update(len(temp["users"]))
                    for item in temp["users"]:
                        followers.append(item)
                        sleep_track += 1
                        if sleep_track >= 20000:
                            sleep_time = randint(120, 180)
                            print("\nWaiting %.2f min. due to too many requests." % float(sleep_time / 60))
                            time.sleep(sleep_time)
                            sleep_track = 0
                    if len(temp["users"]) == 0 or len(followers) >= total_followers:
                        return followers[:total_followers]
                except Exception:
                    return followers[:total_followers]
                if temp["big_list"] is False:
                    return followers[:total_followers]
                next_max_id = temp["next_max_id"]

    def getTotalFollowings(self, usernameId, amount=None):
        sleep_track = 0
        following = []
        next_max_id = ''
        self.getUsernameInfo(usernameId)
        if "user" in self.LastJson:
            if amount:
                total_following = amount
            else:
                total_following = self.LastJson["user"]['following_count']
            if total_following > 200000:
                print("Consider temporarily saving the result of this big operation. This will take a while.\n")
        else:
            return False
        with tqdm(total=total_following, desc="Getting following", leave=False) as pbar:
            while True:
                self.getUserFollowings(usernameId, next_max_id)
                temp = self.LastJson
                try:
                    pbar.update(len(temp["users"]))
                    for item in temp["users"]:
                        following.append(item)
                        sleep_track += 1
                        if sleep_track >= 20000:
                            sleep_time = randint(120, 180)
                            print("\nWaiting %.2f min. due to too many requests." % float(sleep_time / 60))
                            time.sleep(sleep_time)
                            sleep_track = 0
                    if len(temp["users"]) == 0 or len(following) >= total_following:
                        return following[:total_following]
                except Exception:
                    return following[:total_following]
                if temp["big_list"] is False:
                    return following[:total_following]
                next_max_id = temp["next_max_id"]

    def getTotalUserFeed(self, usernameId, minTimestamp=None):
        user_feed = []
        next_max_id = ''
        while 1:
            self.getUserFeed(usernameId, next_max_id, minTimestamp)
            temp = self.LastJson
            if "items" not in temp:  # maybe user is private, (we have not access to posts)
                return []
            for item in temp["items"]:
                user_feed.append(item)
            if "more_available" not in temp or temp["more_available"] is False:
                return user_feed
            next_max_id = temp["next_max_id"]

    def getTotalHashtagFeed(self, hashtagString, amount=100):
        hashtag_feed = []
        next_max_id = ''

        with tqdm(total=amount, desc="Getting hashtag medias", leave=False) as pbar:
            while True:
                self.getHashtagFeed(hashtagString, next_max_id)
                temp = self.LastJson
                try:
                    pbar.update(len(temp["items"]))
                    for item in temp["items"]:
                        hashtag_feed.append(item)
                    if len(temp["items"]) == 0 or len(hashtag_feed) >= amount:
                        return hashtag_feed[:amount]
                except Exception:
                    return hashtag_feed[:amount]
                next_max_id = temp["next_max_id"]

    def getTotalSelfUserFeed(self, minTimestamp=None):
        return self.getTotalUserFeed(self.user_id, minTimestamp)

    def getTotalSelfFollowers(self):
        return self.getTotalFollowers(self.user_id)

    def getTotalSelfFollowings(self):
        return self.getTotalFollowings(self.user_id)

    def getTotalLikedMedia(self, scan_rate=1):
        next_id = ''
        liked_items = []
        for _ in range(0, scan_rate):
            temp = self.getLikedMedia(next_id)
            temp = self.LastJson
            next_id = temp["next_max_id"]
            for item in temp["items"]:
                liked_items.append(item)
        return liked_items
