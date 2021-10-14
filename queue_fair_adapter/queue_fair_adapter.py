from queue_fair_adapter.queue_fair_config import QueueFairConfig
from queue_fair_adapter.queue_fair_logger import QueueFairLogger

import json
import urllib
import traceback
import hashlib
import hmac
import time
import shelve
import os


class QueueFairAdapter:

    COOKIE_NAME_BASE = 'QueueFair-Pass-'

    def __init__(self, service, requestedURL, userAgent,
                 remoteIPAddress, extra):
        self.service = service
        self.continuePage = True
        self.parsing = False
        self.protocol = 'https'
        self.settings = None
        self.adapterResult = None
        self.adapterQueue = None
        self.passedString = None
        self.passedQueues = dict([])
        self.uid = None
        self.requestedURL = requestedURL
        self.userAgent = userAgent
        self.remoteIPAddress = remoteIPAddress
        self.extra = extra
        self.addedCacheControl = False
        self.d = QueueFairConfig.DEBUG

    def setUIDFromCookie(self):
        cookieBase = 'QueueFair-Store-' + QueueFairConfig.ACCOUNT
        uidCookie = self.service.getCookie(cookieBase)
        if uidCookie == '':
            return
        i = uidCookie.find('=')
        if i == -1:
            i = uidCookie.find(':')
        if i == -1:
            if self.d:
                self.log('separator not found in UID Cookie! ' + uidCookie)
            return

        self.uid = uidCookie[i+1:]
        if self.d:
            self.log('UID set to ' + self.uid)

    def checkAndAddCacheControl(self):
        if self.addedCacheControl:
            return
        self.service.addHeader('Cache-Control',
                               'no-store, max-age=0')
        self.addedCacheControl = True

    @staticmethod
    def hash(secret, message):
        signature = hmac.new(
            bytes(secret, 'utf-8'),
            msg=bytes(message, 'utf-8'),
            digestmod=hashlib.sha256
            ).hexdigest().lower()
        return signature

    def validateQuery(self, queue):
        try:
            parsedUrl = urllib.parse.urlparse(self.requestedURL)
            qstr = parsedUrl.query
            q = urllib.parse.parse_qs(qstr)

            if self.d:
                self.log('Validating Passed Query ' + qstr)

            hpos = qstr.rfind('qfh=')
            if hpos == -1:
                if self.d:
                    self.log('No Hash In Query')
                return False

            if 'qfh' not in q:
                if self.d:
                    self.log('Malformed hash')
                return False

            queryHash = q['qfh'][0]

            qpos = qstr.rfind('qfqid=')
            if qpos == -1:
                if self.d:
                    self.log('No Queue Identifier')
                return False

            if 'qfts' not in q:
                if self.d:
                    self.log('No Timestamp')
                return False

            queryTS = q['qfts'][0]

            if not queryTS.isnumeric():
                if self.d:
                    self.log('Timestamp Not Numeric')
                return False

            queryTS = int(queryTS)

            if queryTS > (time.time() +
                          QueueFairConfig.QUERY_TIME_LIMIT_SECONDS):
                if self.d:
                    self.log('Too Late ' +
                             str(queryTS) + ' ' + str(time.time()))
                return False

            if queryTS < (time.time() -
                          QueueFairConfig.QUERY_TIME_LIMIT_SECONDS):
                if self.d:
                    self.log('Too Early ' + str(queryTS) + ' ' +
                             str(time.time()))
                return False

            check = qstr[qpos:hpos]
            checkInput = QueueFairAdapter.processIdentifier(self.userAgent)
            checkInput += check
            checkHash = QueueFairAdapter.hash(queue['secret'], checkInput)

            if checkHash != queryHash:
                if self.d:
                    self.log('Failed Hash')
                return False

            return True
        except Exception as exc:
            if self.d:
                self.log('Error validating query'+str(exc))
            return False

    def validateCookieFromQueue(self, queue, cookie):
        return self.validateCookie(queue['secret'], int(queue['passedLifetimeMinutes']), cookie)

    def validateCookie(self, secret, passedLifetimeMinutes, cookie):
        try:
            if self.d:
                self.log('Validating cookie ' + cookie)
            parsed = urllib.parse.parse_qs(cookie)
            if 'qfh' not in parsed:
                return False
            mHash = parsed['qfh'][0]
            hpos = cookie.rfind('qfh=')
            check = cookie[0:hpos]

            checkInput = QueueFairAdapter.processIdentifier(self.userAgent)
            checkInput += check
            checkHash = QueueFairAdapter.hash(secret, checkInput)
            if mHash != checkHash:
                if self.d:
                    self.log('Cookie Hash Mismatch Given ' + mHash +
                             ' Should be ' + checkHash)
                return False

            tspos = int(parsed['qfts'][0])
            if tspos < time.time() - passedLifetimeMinutes * 60:
                if self.d:
                    self.log('Cookie timestamp too old ' +
                             (time.time() - tspos))
                return False

            if self.d:
                self.log('Cookie Validated ')
            return True
        except Exception as exc:
            if self.d:
                self.log('Cookie Validation failed with error '+str(exc))
            return False

    def checkQueryString(self):
        urlParams = self.requestedURL
        if self.d:
            self.log('Checking URL for Passed String ' + urlParams)

        q = urlParams.find('qfqid=')
        if q == -1:
            return

        if self.d:
            self.log('Passed string found')

        i = urlParams.find('qfq=')
        if i == -1:
            return

        if self.d:
            self.log('Passed String with Queue Name found')

        j = urlParams.find('&', i)
        subStart = i + len('qfq=')
        queueName = urlParams[subStart:j]

        if self.d:
            self.log('Queue name is ' + queueName)

        for queue in self.settings['queues']:
            if queue['name'] != queueName:
                continue

            if self.d:
                self.log('Found queue for querystring ' + queueName)

            value = urlParams
            value = value[value.find('qfqid'):]

            if not self.validateQuery(queue):
                # This can happen if it's a stale query string
                # too - check for valid cookie.
                cName = QueueFairAdapter.COOKIE_NAME_BASE + queueName
                queueCookie = self.service.getCookie(cName)
                if '' != queueCookie:
                    if self.d:
                        self.log('Query validation failed but cookie ' +
                                 queueCookie)
                    if self.validateCookieFromQueue(queue, queueCookie):
                        if self.d:
                            self.log('The cookie is valid. That\'s fine')
                        return

                    if self.d:
                        self.log('Query AND Cookie validation failed!!!')
                else:
                    if self.d:
                        self.log('Bad queueCookie for ' +
                                 queueName + ' ' + queueCookie)

                if self.d:
                    self.log('Query not validl. Redirecting to error page')

                loc = self.protocol + '://' + queue['queueServer'] + '/'
                loc += queue['name'] + '?qfError=InvalidQuery'
                self.redirect(loc, 1)
                return

            if self.d:
                self.log('Query validation succeeded for ' + value)

            self.passedString = value

            self.setCookie(queueName, value,
                           int(queue['passedLifetimeMinutes']) * 60,
                           QueueFairAdapter.optional(queue, 'cookieDomain'))

            if not self.continuePage:
                return

            if self.d:
                self.log('Marking ' + queueName + ' as passed by queryString')

            self.passedQueues[queueName] = True

    def gotSettings(self):
        if self.d:
            self.log('Got client settings.')

        self.checkQueryString()
        if not self.continuePage:
            return
        self.parseSettings()

    def isMatch(self, queue):
        if queue is None:
            return False
        if 'activation' not in queue:
            return False
        if 'rules' not in queue['activation']:
            return False
        return self.isMatchArray(queue['activation']['rules'])

    def isMatchArray(self, arr):
        if arr is None:
            return False
        firstOp = True
        state = False
        i = 0
        for rule in arr:
            i = i+1
            if not firstOp and rule['operator'] is not None:
                if rule['operator'] == 'And' and not state:
                    return False
                elif rule['operator'] == 'Or' and state:
                    return True

            ruleMatch = self.isRuleMatch(rule)
            if firstOp:
                state = ruleMatch
                firstOp = False
                if self.d:
                    self.log('  Rule 1: ' + str(ruleMatch))
            else:
                if self.d:
                    self.log('  Rule ' + (i+1) + ': ' + str(ruleMatch))

                if rule['operator'] == 'And':
                    state = (state and ruleMatch)
                    if not state:
                        break

                elif rule['operator'] == 'Or':
                    state = (state or ruleMatch)
                    if state:
                        break

        if self.d:
            self.log('Final result is ' + str(state))
        return state

    def isRuleMatch(self, rule):
        comp = self.requestedURL
        if rule['component'] == 'Domain':
            comp = comp.replace('http://', '')
            comp = comp.replace('https://', '')
            comp = comp.split('?')[0]
            comp = comp.split('#')[0]
            comp = comp.split('/')[0]
            comp = comp.split(':')[0]
        elif rule['component'] == 'Path':
            domain = comp.replace('http://', '')
            domain = domain.replace('https://', '')
            domain = domain.split('?')[0]
            domain = domain.split('#')[0]
            domain = domain.split('/')[0]
            domain = domain.split(':')[0]
            comp = comp[comp.find(domain) + len(domain):]
            if comp.startswith(':'):
                i = comp.find('/')
                if i != -1:
                    comp = comp[i:]
                else:
                    comp = ''
            i = comp.find('#')
            if i != -1:
                comp = comp[0:i]
            i = comp.find('?')
            if i != -1:
                comp = comp[0:i]
            if comp == '':
                comp = '/'

        elif rule['component'] == 'Query':
            if comp.find('?') == -1:
                comp = ''
            elif comp == '?':
                comp = ''
            else:
                comp = comp[comp.find('?') + 1:]

        elif rule['component'] == 'Cookie':
            comp = self.service.getCookie(rule['name'])

        test = rule['value']

        if not rule['caseSensitive']:
            comp = comp.lower()
            test = test.lower()

        if self.d:
            self.log('  Testing ' + rule['component'] + ' ' + test +
                     ' against ' + comp)

        ret = False

        if rule['match'] == 'Equal' and comp == test:
            ret = True
        elif (rule['match'] == 'Contain' and
              comp is not None and
              comp != '' and comp.find(test) != -1):
            ret = True
        elif rule['match'] == 'Exist':
            if comp is None or '' == comp:
                ret = False
            else:
                ret = True

        if rule['negate']:
            ret = not ret

        return ret

    def isPassed(self, queue):
        if queue['name'] in self.passedQueues:
            if self.d:
                self.log('Queue ' + queue['name'] +
                         ' marked as passed already.')
            return True

        _ = QueueFairAdapter.COOKIE_NAME_BASE + queue['name']
        queueCookie = self.service.getCookie(_)
        if queueCookie == '':
            if self.d:
                self.log('No cookie found for queue ' + queue['name'])
            return False

        if queueCookie.find(queue['name']) == -1:
            if self.d:
                self.log('Cookie value is invalid for ' + queue['name'])
            return False

        if not self.validateCookieFromQueue(queue, queueCookie):
            if self.d:
                self.log('Cookie failed validation ' + queueCookie)
            self.setCookie(queue['name'], '', 0,
                           QueueFairAdapter.optional(queue, 'cookieDomain'))
            return False

        if self.d:
            self.log('Found valid cookie for ' + queue['name'])
        return True

    def onMatch(self, queue):
        if self.isPassed(queue):
            if self.d:
                self.log('Already passed ' + queue['name'] + '.')
            return True
        elif not self.continuePage:
            return False

        if self.d:
            self.log('Checking at server ' + queue['displayName'])
        self.consultAdapter(queue)
        return False

    def setCookie(self, queueName, value, lifetimeSeconds, cookieDomain):
        if self.d:
            self.log('Setting cookie for ' + queueName + ' to ' + value)
        lifetimeSeconds = int(lifetimeSeconds)
        cookieName = QueueFairAdapter.COOKIE_NAME_BASE + queueName
        self.checkAndAddCacheControl()
        self.service.setCookie(cookieName, value,
                               lifetimeSeconds, cookieDomain)

        if lifetimeSeconds > 0:
            self.passedQueues[queueName] = True
            if QueueFairConfig.STRIP_PASSED_STRING:
                loc = self.requestedURL
                pos = loc.find('qfqid=')
                if pos != -1:
                    if self.d:
                        self.log('Stripping passedString from URL')
                    loc = loc[0:pos - 1]
                    self.redirect(loc, 0)

    def log(self, message):
        QueueFairLogger.log(message)

    def redirect(self, loc, sleepSecs):
        if sleepSecs > 0:
            time.sleep(sleepSecs)
        self.checkAndAddCacheControl()
        self.service.redirect(loc)
        self.continuePage = False

    def parseSettings(self):
        if self.settings is None:
            if self.d:
                self.log('ERROR: Settings not set+')
            return

        queues = self.settings['queues']

        if len(queues) == 0:
            if self.d:
                self.log('No queues found+')
            return

        self.parsing = True
        if self.d:
            self.log('Running through queue rules')

        for queue in queues:
            if queue['name'] in self.passedQueues:
                if self.d:
                    self.log('Passed from array ' + queue['name'])
                continue

            if self.d:
                self.log('Checking ' + queue['displayName'])

            if self.isMatch(queue):
                if self.d:
                    self.log('Got a match ' + queue['displayName'])
                if not self.onMatch(queue):
                    if not self.continuePage:
                        return

                    if self.d:
                        self.log('Found matching unpassed queue ' +
                                 queue['displayName'])

                    if QueueFairConfig.ADAPTER_MODE == 'simple':
                        return
                    else:
                        continue

                if not self.continuePage:
                    return

                # Passed.
                self.passedQueues[queue['name']] = True
            else:
                if self.d:
                    self.log('Rules did not match ' + queue['displayName'])

        if self.d:
            self.log('All queues checked')
        self.parsing = False

    @staticmethod
    def urlencode(param):
        return urllib.parse.quote_plus(param)

    @staticmethod
    def urldecode(param):
        return urllib.parse.unquote(param)

    @staticmethod
    def optional(coll, key):
        if key not in coll:
            return None
        return coll[key]

    def consultAdapter(self, queue):
        if self.d:
            self.log('Consulting Adapter Server for queue ' +
                     queue['name']+' for page '+self.requestedURL)
        self.adapterQueue = queue
        adapterMode = 'safe'

        if 'adapterMode' in queue:
            adapterMode = queue['adapterMode']
        elif QueueFairConfig.ADAPTER_MODE is not None:
            adapterMode = QueueFairConfig.ADAPTER_MODE

        if self.d:
            self.log('Adapter mode is ' + adapterMode)

        if 'safe' == adapterMode:
            url = self.protocol + '://' + queue['adapterServer']
            url += '/adapter/' + queue['name']
            url += '?ipaddress='
            url += QueueFairAdapter.urlencode(self.remoteIPAddress)

            if self.uid is not None:
                url += '&uid=' + self.uid

            url += '&identifier='
            url += QueueFairAdapter.urlencode(
                QueueFairAdapter.processIdentifier(self.userAgent))

            if self.d:
                self.log('Adapter URL ' + url)

            js = QueueFairAdapter.urlToJSON(url)
            if js is None:
                self.error('No Settings JSON')
                return
            if self.d:
                self.log('Downloaded JSON Settings ' + str(js))

            self.adapterResult = js
            self.gotAdapter()
            if not self.continuePage:
                return

        else:
            url = self.protocol + '://' + queue['queueServer'] + '/'
            url += queue['name'] + '?target='
            url += QueueFairAdapter.urlencode(self.requestedURL)

            url = self.appendVariant(queue, url)
            url = self.appendExtra(queue, url)

            if self.d:
                self.log('Redirecting to adapter server ' + url)
            self.redirect(url, 0)

    def gotAdapter(self):
        if self.d:
            self.log('Got adapter')

        if not self.adapterResult:
            if self.d:
                self.log('ERROR: onAdapter() called without result')
            return

        if 'uid' in self.adapterResult:
            if self.uid is not None and self.uid != self.adapterResult['uid']:
                self.log(
                    'UID Cookie Mismatch - expected ' +
                    self.uid + ' but received ' + self.adapterResult['uid']
                )
            else:
                self.uid = self.adapterResult['uid']
                self.service.setCookie('QueueFair-Store-' +
                                       QueueFairConfig.ACCOUNT,
                                       'u:' + self.uid,
                                       self.adapterResult['cookieSeconds'],
                                       self.optional(self.adapterQueue,
                                                     'cookieDomain'))

        if 'action' not in self.adapterResult:
            if self.d:
                self.log('ERROR: gotAdapter() called without result action')
            return

        if self.adapterResult['action'] == 'SendToQueue':
            if self.d:
                self.log('Sending to queue server')
            queryParams = ''
            target = self.requestedURL
            if self.adapterQueue['dynamicTarget'] != 'disabled':
                if self.adapterQueue['dynamicTarget'] == 'path':
                    i = target.find('?')
                    if i != -1:
                        target = target[0:i]

            queryParams += 'target='
            queryParams += QueueFairAdapter.urlencode(target)

            if self.uid is not None:
                if queryParams != '':
                    queryParams += '&'

                queryParams += 'qfuid=' + self.uid

            redirectLoc = self.adapterResult['location']
            if queryParams != '':
                redirectLoc = redirectLoc + '?' + queryParams

            redirectLoc = self.appendVariant(self.adapterQueue, redirectLoc)
            redirectLoc = self.appendExtra(self.adapterQueue, redirectLoc)

            if self.d:
                self.log('Redirecting to ' + redirectLoc)
            self.redirect(redirectLoc, 0)
            return

        # SafeGuard etc
        self.setCookie(self.adapterResult['queue'],
                       QueueFairAdapter.urldecode(
                           self.adapterResult['validation']),
                       int(self.adapterQueue['passedLifetimeMinutes']) * 60,
                       self.optional(self.adapterQueue, 'cookieDomain'))

        if not self.continuePage:
            return

        if self.d:
            self.log('Marking ' + self.adapterResult['queue'] +
                     ' as passed by adapter')

        self.passedQueues[self.adapterResult['queue']] = True

    def appendVariant(self, queue, redirectLoc):
        if self.d:
            self.log('Looking for variant')

        variant = self.getVariant(queue)
        if variant is None:
            if self.d:
                self.log('No variant found')
            return redirectLoc

        if self.d:
            self.log('Found variant ' + variant)

        if redirectLoc.find('?') != -1:
            redirectLoc += '&'
        else:
            redirectLoc += '?'

        redirectLoc += 'qfv=' + QueueFairAdapter.urlencode(variant)
        return redirectLoc

    def appendExtra(self, queue, redirectLoc):
        if self.extra == '' or self.extra is None:
            return redirectLoc

        self.log('Found extra ' + self.extra)

        if redirectLoc.find('?') != -1:
            redirectLoc += '&'
        else:
            redirectLoc += '?'

        redirectLoc += 'qfx=' + QueueFairAdapter.urlencode(self.extra)
        return redirectLoc

    def getVariant(self, queue):
        if self.d:
            self.log('Getting variants for ' + queue['name'])

        if 'activation' not in queue:
            return None

        if 'variantRules' not in queue['activation']:
            return None

        variantRules = queue['activation']['variantRules']

        if self.d:
            self.log('Checking variant rules for ' + queue['name'])

        for variant in variantRules:
            variantName = variant.variant
            rules = variant.rules
            ret = self.isMatchArray(rules)
            if self.d:
                self.log('Variant match ' + variantName + ' ' + ret)
            if ret:
                return variantName
        return None

    @staticmethod
    def processIdentifier(parameter):
        if parameter is None:
            return None
        i = parameter.find('[')
        if i == -1:
            return parameter
        if i < 20:
            return parameter
        return parameter[0:i]

    @staticmethod
    def urlToJSON(url):
        return json.loads(urllib.request.urlopen(url).read())

    def settingsURL(self):
        ret = self.protocol + '://'
        ret += QueueFairConfig.FILES_SERVER+'/'+QueueFairConfig.ACCOUNT+'/'
        ret += QueueFairConfig.ACCOUNT_SECRET+'/queue-fair-settings.json'
        return ret

    @staticmethod
    def create(filename):
        try:
            with open(filename, 'x') as _:
                return False
        except FileExistsError:
            return True

    def writeToShelf(self):
        # Only one process may write to the shelf at a time,
        # and there must be no reads while writing.
        if QueueFairAdapter.create(QueueFairAdapter.getSettingsLockLoc()):
            self.settings = QueueFairAdapter.urlToJSON(self.settingsURL())
            if self.d:
                self.log("Settings lock exists!")
            return

        try:
            self.settings = QueueFairAdapter.urlToJSON(self.settingsURL())
            d = shelve.open(QueueFairAdapter.getSettingsLoc(), 'c', None, True)
            d['time'] = time.time()
            d['settings'] = self.settings
            d.close()
            if self.d:
                self.log("Written settings to shelf")
        except Exception as exc:
            if self.d:
                self.log("Unexpected error storing settings from  " +
                         self.settingsURL() + ": " + str(exc))
        finally:
            os.remove(QueueFairAdapter.getSettingsLockLoc())

    def waitForSettings(self):
        unlocked = False
        for x in range(0, QueueFairConfig.READ_TIMEOUT):
            if not os.path.exists(QueueFairAdapter.getSettingsLockLoc()):
                unlocked = True
                break
            if self.d:
                self.log('Sleeping '+str(x))
            time.sleep(1)
        if unlocked:
            return
        if self.d:
            self.log('Deleting lock')
        os.remove(QueueFairConfig.SETTINGS_FILE_CACHE_LOCATION+'/SettingsLock')

    @staticmethod
    def getSettingsLoc():
        w = QueueFairConfig.SETTINGS_FILE_CACHE_LOCATION
        return w + '/QueueFairStoredSettings'

    @staticmethod
    def getSettingsLockLoc():
        return QueueFairConfig.SETTINGS_FILE_CACHE_LOCATION+'/SettingsLock'

    def loadSettings(self):
        if 'DELETE' in QueueFairConfig.ACCOUNT:
            raise ValueError('QF bad account name - edit QueueFairConfig.py')

        self.waitForSettings()
        d = None
        # You can have as many read processes as you like.
        try:
            d = shelve.open(QueueFairAdapter.getSettingsLoc(), 'r')
        except Exception:
            self.writeToShelf()
            if self.d:
                self.log('Created settings storage')
            return

        if 'time' not in d:
            d.close()
            self.writeToShelf()
            if self.d:
                self.log("Time not in shelf!.")
            return
        else:
            if 'settings' in d:
                if (time.time() - d['time'] <
                        QueueFairConfig.SETTINGS_FILE_CACHE_LIFETIME_MINUTES *
                        60):
                    self.settings = d['settings']
                    d.close()
                    if self.d:
                        self.log("Retrieved settings from cache.")
                    return
                else:
                    d.close()
                    self.writeToShelf()
                    if self.d:
                        self.log("Refreshed cached settings.")
                    return
            else:
                d.close()
                self.writeToShelf()
                if self.d:
                    self.log("Time in shelf but not settings!")
                return

    def isContinue(self):
        try:
            if self.d:
                self.log('----Adapter Starting for '+self.remoteIPAddress)
            self.setUIDFromCookie()
            self.loadSettings()
            if self.settings is None:
                return True
            self.gotSettings()

            if self.d:
                self.log('----Adapter Ending for '+self.remoteIPAddress)
            return self.continuePage
        except Exception as exc:
            print('QF ----Adapter Ending with Exception')
            print(exc)
            print(traceback.format_exc())
        return True
