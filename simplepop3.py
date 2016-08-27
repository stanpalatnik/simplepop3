from functools import reduce
import os
import SocketServer
import threading
import logging
import sys
import glob
import errno

OK = u'+OK'
ERR = u'-ERR'

logdir = u'/var/log/simplepop3'


def mkdir_p(path):
    """http://stackoverflow.com/a/600612/190597 (tzot)"""
    try:
        os.makedirs(path, exist_ok=True)  # Python>3.2
    except TypeError:
        try:
            os.makedirs(path)
        except OSError as exc: # Python >2.5
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else: raise

mkdir_p(os.path.dirname(logdir))
logger = logging.getLogger('POP3Server')
logger.addHandler(logging.StreamHandler(sys.stderr))
logger.addHandler(logging.FileHandler('/var/log/simplepop3/simplepop3.log'))
for h in logger.handlers:
    h.setFormatter(logging.Formatter(fmt='%(asctime)s [%(name)s.%(levelname)s %(lineno)d]: %(message)s'))
logger.setLevel(logging.DEBUG)


class Message(object):
    def __init__(self, filename):
        msg = open(filename, "r")
        try:
            self.data = data = msg.read()
            self.size = len(data)
            self.headers, bot = data.split("\r\n\r\n", 1)
            self.body = bot.split("\r\n")
        finally:
            msg.close()

    def __len__(self):
        return len(self.data)

    def as_string(self):
        """return the complete message"""
        return self.data


def load_messages(path):
    return map(to_message, glob.glob(os.path.join(path, '*.eml')))


def to_message(filename):
    Message(filename)


class POP3ServerProtocol(SocketServer.BaseRequestHandler):

    def setup(self):
        self.state = u'authorization'
        self.messages = load_messages(self.server.message_path)
        self._pop3user = False
        self._pop3pass = False
        logger.debug(u'S: %s POP3 server ready' % OK)
        self.request.sendall(u'%s\r\n' % self.banner())

    def banner(self):
        """the authorization or welcome banner"""
        return u'%s SilverSky POP3 server ready' % OK

    def quit(self):
        """quit transaction and session command"""
        self.state = u'closed'
        return u'%s POP3 server signing off' % OK

    def stat(self):
        """stat command returns count and size of messages to the MUA"""
        if self.state not in (u'transaction',):
            return u'%s POP3 invalid state for command %s' % (ERR, u'STAT')
        return u'%s %d %d' % (OK, len(self.messages), self.__get_messagesize__())

    def list(self, msg_idx=None):
        """list command returns either one specific or without arguments a list of all messages enumerated and size
        Examples::
            C:    LIST
            S:    +OK 2 messages (320 octets)
            S:    1 120
            S:    2 200
            S:    .
                  ...
            C:    LIST 2
            S:    +OK 2 200

        """
        if self.state not in (u'transaction',):
            return u'%s POP3 invalid state for command %s' % (ERR, u'LIST')
        if msg_idx is not None:
            try:
                content = self.__get_msg__(msg_idx)
            except IndexError:
                return u'%s no such message, only %s messages found' % (ERR, len(self.messages))
            return u'%s %s %s' % (OK, msg_idx, len(content))
        else:
            msg_idx = []
            for n, m in enumerate(self.messages):
                n += 1
                msg_idx.append(u'%s %s' % (n, m.size))
            return u'%s %s (%s octets)\r\n%s\r\n.' % (OK, len(self.messages), self.__get_messagesize__(), '\r\n'.join(msg_idx))

    def retr(self, msg_idx=None):
        """retr command returns a complete specific message"""
        if self.state not in (u'transaction',):
            return u'%s POP3 invalid state for command %s' % (ERR, u'RETR')
        try:
            message = self.__get_msg__(msg_idx)
        except IndexError:
            return u'%s no such message, only %s messages found' % (ERR, len(self.messages))
        return u'%s %s octets\r\n%s\r\n.' % (
        OK, len(message.size), unicode(message.as_string(), 'utf8').encode('ascii', 'ignore'))

    def noop(self):
        """noop command for idle connections to avoid tcp timeouts on firewalls or similar"""
        return u'%s' % OK

    def user(self, name=None):
        """user command sets the user credentials part"""
        if self.state not in (u'authorization',):
            return u'%s POP3 invalid state for command %s' % (ERR, u'USER')
        self._pop3user = name
        return u'%s' % OK

    def password(self, credentials=None):
        """pass command sets the password credentials part"""
        if self.state not in (u'authorization',):
            return u'%s POP3 invalid state for command %s' % (ERR, u'PASS')
        if credentials is None:
            return u'%s invalid password' % ERR
        logger.debug(u'trying to login for %s' % self._pop3user)
        self.state = u'transaction'
        return u'%s' % OK

    def __get_msg__(self, num=None):
        num = int(num) - 1
        return self.messages[num]

    def __get_messagesize__(self):
        return reduce((lambda x, y: x + y), map((lambda x: len(x)), self.messages))

    def handle(self):
        """core routing"""
        while True:
            self.data = self.request.recv(1024).strip()
            try:
                cmd, cmd_options = self.data.split(None, 1)
                cmd = cmd.lower()
            except ValueError:
                try:
                    cmd = self.data.split()[0].lower()
                except IndexError:
                    cmd = 'quit'
                cmd_options = False
            call = getattr(self, cmd, False)
            try:
                logger.debug(u'C: %s' % unicode(cmd, 'utf8').encode('ascii', 'ignore'))
            except:
                logger.error(u'cannot decode client output')
            if call:
                if not cmd_options:
                    rsp = call()
                    logger.debug(u'S: %s' % str(rsp))
                    self.request.sendall(u'%s\r\n' % str(rsp))
                else:
                    rsp = call(cmd_options)
                    if cmd in ('retr',):
                        logger.debug(u'S: %s' % str(rsp).split('\r\n')[0])
                    else:
                        logger.debug(u'S: %s' % str(rsp))
                    self.request.sendall(u'%s\r\n' % str(rsp))
                if cmd == 'quit':   break
            else:
                try:
                    logger.debug(u'%s POP3 doesn\'t support command %s\r\n' % (
                    ERR, unicode(cmd, 'utf8').encode('ascii', 'ignore')))
                except:
                    logger.error(u'%s POP3 doesn\'t support command output cannot be decoded' % ERR)
                self.request.sendall(u'%s POP3 doesn\'t support command\r\n' % (ERR))


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


def main(options):
    try:
        logger.debug(u'using ThreadedTCPServer(%s:%s)' % (options.listen, options.port))
        server = ThreadedTCPServer((options.listen, options.port), POP3ServerProtocol)
    except IndexError:
        server = ThreadedTCPServer((options.listen, options.port), POP3ServerProtocol)
    server.message_path = options.path
    logger.info(u'serving POP3 service at %s:%s' % server.server_address)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    logger.debug(u'serving forever')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.shutdown()


if __name__ == '__main__':
    import sys
    import optparse
    import daemon
    import lockfile

    parser = optparse.OptionParser()
    parser.add_option('-l', '--listen', action='store', default='127.0.0.1')
    parser.add_option('-p', '--port', action='store', type=int, default=110)
    parser.add_option('-d', '--debug', action='store_true', default=False)
    parser.add_option('-m', '--path', action='store', default='.')
    parser.add_option('--daemon', action='store_true', default=True)

    options, remainings = parser.parse_args()
    if options.debug:
        logger.setLevel(logging.DEBUG)

    if options.daemon:
        loghandlers = []
        for h in logger.handlers:
            loghandlers.append(h.stream)
        with daemon.DaemonContext(working_directory='/tmp/',
                                  pidfile=lockfile.FileLock(path='/tmp/pop3server.lock'),
                                  files_preserve=loghandlers,
                                  uid=99, gid=99,
                                  ):
            main(options)
        logger.info(u'shutting down on request')
    else:
        main(options)
